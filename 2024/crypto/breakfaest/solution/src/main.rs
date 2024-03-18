use volonym::{Fr, FVec, SparseFMatrix, zkp::{R1CSWithMetadata, R1CS::Sparse, SparseR1CS}, SparseVec};
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
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::net::TcpStream;
use base64::{prelude::BASE64_STANDARD, Engine};

mod actors_modified;
use actors_modified::{CommitAndProof, Prover};

const CHAL_ADDR: &str = "127.0.0.1:8008";

fn main()
{
    let mut remote = TcpStream::connect(CHAL_ADDR).unwrap();
    let mut r = BufReader::new(remote.try_clone().unwrap());

    let pub_key = recv_until(&mut r, "My public key: ");
    let pub_key = BASE64_STANDARD.decode(&pub_key[..pub_key.len()].trim_end()).unwrap();
    let pub_key = Key::deserialize(pub_key.as_slice()).unwrap();
    println!("Received public key: {:?}", pub_key);

    let msg = "Give me the flag!";
    recv_until(&mut r, "Please sign a message.");
    recv_until(&mut r, "Message:");
    writeln!(&mut remote, "{}", msg).unwrap();

    // Use forgery attack to sign the message.
    let signature = pub_key.sign(msg.as_bytes());
    //println!("Signature: {:?}", signature);

    let signature = serde_bare::to_vec(&signature).unwrap();
    writeln!(&mut remote, "{}", BASE64_STANDARD.encode(&signature));
    recv_until(&mut r, "Signature:");

    loop {
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        if line.len() == 0 {
            break;
        }
        print!("{}", line);
    }
}

fn recv_until<R: BufRead>(mut r: R, line_prefix: &str) -> String {
    loop {
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        if line.starts_with(line_prefix) {
            return String::from(&line[line_prefix.len()..]);
        }
    }
}

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

    // Sign a message, without actually using the witness (i.e., without the private key).
    pub fn sign(&self, message: &[u8]) -> Signature {
        let msg_digest = Self::message_digest(message);

        let cs = ConstraintSystem::<ArkF>::new_ref();
        cs.set_mode(SynthesisMode::Setup);
        let _digest_var = FpVar::new_input(cs.clone(), || Ok(msg_digest)).unwrap();
        self.generate_constraints(cs.clone()).unwrap();
        cs.inline_all_lcs();

        let public_vars = [Fr::from(1), from_ark_field(msg_digest), from_ark_field(self.pk)];
        let constraint_mats = cs.to_matrices().unwrap();
        let mut prover = Prover::from_public_vars_and_circuit_unpadded(&public_vars, convert_r1cs(constraint_mats));

        // Actual forgery attack is in prove(), which is called by commit_and_prove().
        prover.commit_and_prove().unwrap()
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
