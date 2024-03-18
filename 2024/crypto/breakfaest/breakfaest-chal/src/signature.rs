use volonym::{Fr, FVec, SparseFMatrix, actors::actors::{CommitAndProof, Prover, Verifier}, zkp::{R1CSWithMetadata, R1CS::Sparse, SparseR1CS}, SparseVec};
use arkworks_native_gadgets::poseidon::{FieldHasher, Poseidon, PoseidonParameters, sbox::PoseidonSbox};
use arkworks_r1cs_gadgets::poseidon::{FieldHasherGadget, PoseidonGadget};
use arkworks_utils::{Curve, bytes_matrix_to_f, bytes_vec_to_f, poseidon_params::setup_poseidon_params};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, Matrix, SynthesisError, SynthesisMode, Variable};
use ark_bn254::Fr as ArkF;
use ark_ff::{PrimeField};
use rand::{CryptoRng, Rng};
use sha2::{Sha256, Digest};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, SerializationError};
use std::io::Write;
use std::io::Read;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Key {
    sk: Option<ArkF>,
    pk: ArkF,
}

type Signature = CommitAndProof<Fr>;

impl Key {
    pub fn generate<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> Key {
        let mut secret = [0u8; 64];
        rng.fill_bytes(&mut secret);
        let sk = ArkF::from_le_bytes_mod_order(&secret);

        let pk = poseidon().hash(&[sk]).unwrap();
        Key {
            sk: Some(sk),
            pk: pk,
        }
    }

    pub fn public_key(&self) -> Key {
        Key { sk: None, pk: self.pk }
    }

    fn message_digest(message: &[u8]) -> ArkF {
        let msg_digest = Sha256::digest(message);
        ArkF::from_le_bytes_mod_order(msg_digest.as_ref())
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let msg_digest = Self::message_digest(message);

        let cs = ConstraintSystem::<ArkF>::new_ref();
        cs.set_mode(SynthesisMode::Prove { construct_matrices: true });
        let _digest_var = FpVar::new_input(cs.clone(), || Ok(msg_digest)).unwrap();
        self.generate_constraints(cs.clone()).unwrap();
        cs.inline_all_lcs();

        let constraint_mats = cs.to_matrices().unwrap();
        let mut prover = Prover::from_witness_and_circuit_unpadded(convert_witness(&cs), convert_r1cs(constraint_mats));

        prover.commit_and_prove().unwrap()
    }

    pub fn verify(&self, message: &[u8], signature: Signature) -> Option<()> {
        let msg_digest = Self::message_digest(message);

        let cs = ConstraintSystem::<ArkF>::new_ref();
        let _digest_var = FpVar::new_input(cs.clone(), || Ok(msg_digest)).unwrap();
        cs.set_mode(SynthesisMode::Setup);
        self.generate_constraints(cs.clone()).unwrap();
        cs.inline_all_lcs();

        let constraint_mats = cs.to_matrices().unwrap();
        let verifier = Verifier::from_circuit(convert_r1cs(constraint_mats));

        let public_vars = verifier.verify(&signature).ok()?;
        if public_vars.public_inputs.len() != 3 || public_vars.public_outputs != [] ||
           public_vars.public_inputs[0] != Fr::from(1) ||
           public_vars.public_inputs[1] != from_ark_field(msg_digest) ||
           public_vars.public_inputs[2] != from_ark_field(self.pk) {
            return None;
        }

        Some(())
    }
}

impl ConstraintSynthesizer<ArkF> for &Key {
    fn generate_constraints(self, mut cs: ConstraintSystemRef<ArkF>) -> Result<(), SynthesisError> {
        let poseidon = PoseidonGadget::from_native(&mut cs, poseidon())?;
        let x = FpVar::new_witness(cs.clone(), || self.sk.ok_or(SynthesisError::AssignmentMissing))?;
        let y = poseidon.hash(&[x])?;
        let y_pk = FpVar::new_input(cs.clone(), || Ok(self.pk))?;
        y.enforce_equal(&y_pk)
    }
}

fn poseidon() -> Poseidon::<ArkF> {
    let data = setup_poseidon_params(Curve::Bn254, 5, 3).unwrap();

    let params = PoseidonParameters {
        mds_matrix: bytes_matrix_to_f(&data.mds),
        round_keys: bytes_vec_to_f(&data.rounds),
        full_rounds: data.full_rounds,
        partial_rounds: data.partial_rounds,
        sbox: PoseidonSbox(data.exp),
        width: data.width,
    };

    Poseidon::<ArkF>::new(params)
}

fn from_ark_field<F: ff::PrimeField>(x: ArkF) -> F {
    let x_repr = x.into_repr();
    let x_limbs: &[u64] = x_repr.as_ref();

    let mut out = F::ZERO;
    let pow64 = F::from_u128(1u128 << 64);
    for digit in x_limbs.iter().rev() {
        out.mul_assign(pow64);
        out.add_assign(F::from(*digit));
    }
    out
}

fn convert_r1cs(constraints: ConstraintMatrices<ArkF>) -> R1CSWithMetadata<Fr> {
    fn convert_mat(mat: Matrix<ArkF>) -> SparseFMatrix<Fr> {
        SparseFMatrix(mat.into_iter().map(
            |row| SparseVec(row.into_iter().map(
                |(coeff, index)| (index, from_ark_field::<Fr>(coeff))
            ).collect())
        ).collect())
    }

    let r1cs = SparseR1CS {
        a_rows: convert_mat(constraints.a),
        b_rows: convert_mat(constraints.b),
        c_rows: convert_mat(constraints.c),
    };

    let public_inputs = (0 .. constraints.num_instance_variables).collect();

    R1CSWithMetadata {
        r1cs: Sparse(r1cs),
        public_inputs_indices: public_inputs,
        public_outputs_indices: Vec::new(),
        unpadded_wtns_len: constraints.num_instance_variables + constraints.num_witness_variables,
    }
}

fn convert_witness(cs: &ConstraintSystemRef<ArkF>) -> FVec<Fr> {
    let mut witness = Vec::new();

    for i in 0 .. cs.num_instance_variables() {
        witness.push(from_ark_field(cs.assigned_value(Variable::Instance(i)).unwrap()))
    }
    for i in 0 .. cs.num_witness_variables() {
        witness.push(from_ark_field(cs.assigned_value(Variable::Witness(i)).unwrap()))
    }

    FVec(witness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
    use std::str::FromStr;

    const POSEIDON_KAT_IN: &str = "7022600137302410879196823731391398217610755469249182300842136417747197818110";
    const POSEIDON_KAT_OUT: &str = "3449853715625423859292873209506761211977221729626328519546202226488098208487";

    #[test]
    fn poseidon_kat() {
        let poseidon = poseidon();
        assert_eq!(poseidon.hash(&[ArkF::from_str(POSEIDON_KAT_IN).unwrap()]).unwrap(),
                   ArkF::from_str(POSEIDON_KAT_OUT).unwrap());
    }

    #[test]
    fn poseidon_gadget_kat() {
        let k = Key {
            sk: Some(ArkF::from_str(POSEIDON_KAT_IN).unwrap()),
            pk: ArkF::from_str(POSEIDON_KAT_OUT).unwrap(),
        };

        let cs = ConstraintSystem::<ArkF>::new_ref();
        cs.set_mode(SynthesisMode::Prove { construct_matrices: true });
        k.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn prove_verify() {
        let k = Key::generate(&mut StdRng::from_entropy());

        let msg = b"Test";
        let proof = k.sign(msg);
        k.verify(msg, proof).unwrap();
    }

    #[test]
    fn prove_verify_kat() {
        let k = Key {
            sk: Some(ArkF::from_str(POSEIDON_KAT_IN).unwrap()),
            pk: ArkF::from_str(POSEIDON_KAT_OUT).unwrap(),
        };

        let proof = k.sign(b"Test KAT");
        k.verify(b"Test KAT", proof).unwrap();
    }

    #[test]
    fn prove_verify_serialized() {
        let k = Key::generate(&mut StdRng::from_entropy());

        let msg = b"Test";
        let proof = serde_bare::to_vec(&k.sign(msg)).unwrap();
        k.verify(msg, serde_bare::from_slice(&proof).unwrap()).unwrap();
    }
}
