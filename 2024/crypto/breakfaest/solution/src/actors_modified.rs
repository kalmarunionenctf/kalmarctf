use anyhow::{Error, anyhow, Ok};
use blake3::hash;
use ff::{PrimeField, Field};
use rand::{rngs::ThreadRng, RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use serde::{Serialize, Deserialize};
use volonym::{subspacevole::{RAAACode, calc_consistency_check, LinearCode}, DotProduct, FVec, FMatrix, zkp::{R1CS, quicksilver::{ZKP, self}, R1CSWithMetadata}, vecccom::{commit_seeds, commit_seed_commitments, proof_for_revealed_seed, reconstruct_commitment}, smallvole::{ProverSmallVOLEOutputs, self, VOLE}, challenges::{challenge_from_seed, calc_other_challenges}, PF};

// Use some of the original structs unchanged.
pub use volonym::actors::actors::{CommitAndProof, Proof, ProverCommitment, PublicOpenings, PublicUOpenings, SubspaceVOLEOpening};


const NUM_VOLES: u32 = 1024;

pub struct Prover<T: PF> {
    pub code: RAAACode,
    pub vole_length: usize,
    pub num_voles: usize,
    pub witness: FMatrix<T>,
    pub circuit: R1CSWithMetadata<T>,
    pub subspace_vole_secrets: Option<SubspaceVOLESecrets<T>>,
}

// Copied, because original had private members.
pub struct SubspaceVOLESecrets<T: PF> {
    pub seeds: Vec<([[u8; 32]; 2])>,
    pub u1: FMatrix<T>,
    pub u2: FMatrix<T>,
    pub v1: FMatrix<T>,
    pub v2: FMatrix<T>
}

// Copies of FVec::scalar_mul and FMatrix::scalar_mul, since the originals are private.
pub fn scalar_mul_fvec<T: PF>(s: &FVec<T>, rhs: T) -> FVec<T> {
    FVec(s.0.iter().map(|a| *a * rhs).collect())
}
pub fn scalar_mul_fmat<T: PF>(s: &FMatrix<T>, rhs: T) -> FMatrix<T> {
    FMatrix(
        s.0.iter().map(|x|scalar_mul_fvec(x, rhs)).collect()
    )
}

fn get_quicksilver_universal_hashes<T: PF>(seed_comm: &[u8; 32], nrows: usize, ncols: usize) -> [FVec<T>; 2] {
    let universal_inner = challenge_from_seed(seed_comm, &"quicksilver_inner".as_bytes(), nrows);
    let universal_outer = challenge_from_seed(seed_comm, &"quicksilver_outer".as_bytes(), ncols);
    return [universal_inner, universal_outer];
}

// Copied from challenges::calc_quicksilver_challenge, to allow refactoring.
fn calc_quicksilver_challenge<T: PF>(seed_comm: &[u8; 32], witness_comm: &FMatrix<T>) -> T {
    let [universal_inner, universal_outer] =
        get_quicksilver_universal_hashes(seed_comm, witness_comm.0.len(), witness_comm.0[0].0.len());

    // VULN: challenge only depends on a linear function of witness_comm.
    let compressed = universal_outer.dot(
        &(&universal_inner * witness_comm)
    );
    let digest = *blake3::hash(&compressed.to_u8s()).as_bytes();
    T::random(&mut ChaCha12Rng::from_seed(digest))
}

// Copied from quicksilver::get_challenge_vec because it was private.
fn qs_get_challenge_vec<T: PF>(challenge: &T, length: usize) -> FVec<T> {
    let mut challenge_vec = Vec::with_capacity(length);
        challenge_vec.push(challenge.clone());
        for i in 1..length {
            challenge_vec.push(challenge_vec[i-1] * challenge);
        }
    FVec::<T>(challenge_vec)
}

impl<T: PF> Prover<T> {
    pub fn from_public_vars_and_circuit_unpadded(public_vars: &[T], mut circuit: R1CSWithMetadata<T>) -> Self {
        let code = RAAACode::rand_default();
        let k = code.k();
        let pp = circuit.calc_padding_needed(k);

        // Start out with an all zeroes witness (except for the public variables. It'll be adjusted later.
        let mut witness = FVec(Vec::from(public_vars));
        witness.zero_pad(circuit.unpadded_wtns_len + pp.pad_len - witness.0.len());
        circuit.r1cs.zero_pad(pp.pad_len);
        let mut witness_rows = Vec::with_capacity(pp.num_padded_wtns_rows);

        let mut start_idx = 0;
        for _i in 0..pp.num_padded_wtns_rows {
            witness_rows.push(FVec::<T>(
                witness.0.get(start_idx .. start_idx + k).expect("This panic should not be reached").to_vec()
            ));
            start_idx += k;
        }

        circuit.r1cs.zero_pad(pp.pad_len);

        Self {
            num_voles: code.n(),
            vole_length: 2 * (pp.num_padded_wtns_rows + 1),
            code,
            circuit,
            witness: FMatrix(witness_rows),
            subspace_vole_secrets: None,
        }
    }

    // Almost unchanged.
    pub fn mkvole(&mut self) -> Result<ProverCommitment<T>, Error> {
        if self.num_voles < 1024 { eprintln!("Less than 1024 VOLEs could result in <128 bits of soundness with current parameters for linear codes"); }
        let mut rng = ThreadRng::default();
        let mut seeds: Vec<[[u8; 32]; 2]> = vec![[[0u8; 32]; 2]; self.num_voles];
        let mut seed_commitments = Vec::with_capacity(self.num_voles);
        let mut vole_outputs = Vec::with_capacity(self.num_voles);
        let sv = smallvole::VOLE::init();
        for i in 0..self.num_voles {
            rng.fill_bytes(&mut seeds[i][0]);
            rng.fill_bytes(&mut seeds[i][1]);
            seed_commitments.push(commit_seeds(&seeds[i][0], &seeds[i][1]));
            vole_outputs.push(sv.prover_outputs(&seeds[i][0], &seeds[i][1], self.vole_length));
        }

        let seed_comm = commit_seed_commitments(&seed_commitments);

        let u_prime_cols = FMatrix(vole_outputs.iter().map(|o|o.u.clone()).collect::<Vec<FVec::<T>>>());
        let v_cols = FMatrix(vole_outputs.iter().map(|o|o.v.clone()).collect::<Vec<FVec::<T>>>());

        let u_prime_rows = u_prime_cols.transpose();
        let v_rows = v_cols.transpose();

        let (new_u_rows, correction) = self.code.get_prover_correction(&u_prime_rows);

        let witness_comm = &self.witness - &FMatrix(new_u_rows.0[0..self.witness.0.len()].to_vec());

        if self.num_voles % self.code.q != 0 { return Err(anyhow!("invalid num_voles param")) };
        let challenge_hash = challenge_from_seed(&seed_comm, "vole_consistency_check".as_bytes(), self.vole_length);
        let consistency_check = calc_consistency_check(&challenge_hash, &new_u_rows.transpose(), &v_cols);


        let u_len = new_u_rows.0.len();
        let v_len = v_rows.0.len();

        if !(u_len % 2 == 0) { return Err(anyhow!("Number of u's rows must be even")) }
        if !(v_len % 2 == 0) { return Err(anyhow!("Number of v's rows must be even")) }

        let half_u_len = u_len / 2;
        let half_v_len = v_len / 2;

        let u1 = FMatrix(new_u_rows.0[0..half_u_len].to_vec());
        let u2 = FMatrix(new_u_rows.0[half_u_len..u_len].to_vec());

        let v1 = FMatrix(v_rows.0[0..half_v_len].to_vec());
        let v2 = FMatrix(v_rows.0[half_v_len..v_len].to_vec());

        self.subspace_vole_secrets = Some(SubspaceVOLESecrets {
            seeds,
            u1,
            u2,
            v1,
            v2,
        });
        Ok(ProverCommitment {
            seed_comm,
            witness_comm,
            consistency_check,
            subspace_vole_correction: correction
        })
    }

    // Unchanged.
    fn s_matrix_with_consistency_proof(&self, vith_delta: &T, challenge: &FVec<T>) -> Result<(FMatrix<T>, FVec<T>), Error> {
        let svs = self.subspace_vole_secrets.as_ref().ok_or(anyhow!("VOLE must be completed before this step"))?;
        let s = &scalar_mul_fmat(&svs.u1, *vith_delta) + &svs.u2;
        let proof = challenge * &(&scalar_mul_fmat(&svs.v1, *vith_delta) + &svs.v2).transpose();
        Ok((s, proof))
    }

    pub fn prove(&mut self, comm: &mut ProverCommitment<T>) -> Result<Proof<T>, Error> {
        let err_uncompleted = ||anyhow!("VOLE must be completed before this step");
        let svs = self.subspace_vole_secrets.as_ref().ok_or(err_uncompleted())?;
        let seed_comm = &mut comm.seed_comm;
        let witness_comm = &mut comm.witness_comm;

        let challenge = calc_quicksilver_challenge(seed_comm, &witness_comm);
        let prover = quicksilver::Prover::from_vith(svs.u1.clone(), svs.u2.clone(), self.witness.clone(), self.circuit.clone());

        // The actually attack: adjust witness_comm so that the linear combination of constraints
        // sampled by challenge is satisfied, even if few (or none) of the the constraints are.
        // Since challenge is only based on a linear function of witness_comm, we just need to keep
        // this linear function the same while adjusting witness_comm.

        let r1cs = match &self.circuit.r1cs {
            R1CS::Full(_f) => unimplemented!(),
            R1CS::Sparse(s) => s,
        };

        // First: compute the universal hashes.
        let [universal_inner, universal_outer]: [FVec<T>; 2] =
            get_quicksilver_universal_hashes(seed_comm, witness_comm.0.len(), witness_comm.0[0].0.len());
        let qs_challenge_vec = qs_get_challenge_vec::<T>(&challenge, svs.u1.0.len() * svs.u1.0[0].0.len());

        // Second: find the error in the linear combination of the constraints selected by
        // challenge.
        let (u_a, u_b, u_c) = (&prover.u * &r1cs.a_rows, &prover.u * &r1cs.b_rows, &prover.u * &r1cs.c_rows);
        let qs_error_vec = &(&u_a * &u_b) - &u_c;
        let qs_error = qs_error_vec.dot(&qs_challenge_vec);

        // Finally: solve for a change in the witness that will correct this error while keeping
        // challenge unchanged. To avoid solving a quadratic equation, search for variables that
        // only affect the constraints linearly.
        let mut linear_vars = vec![true; self.circuit.unpadded_wtns_len];

        // Don't modify the public variables.
        for i in &self.circuit.public_inputs_indices { linear_vars[*i] = false; }
        for i in &self.circuit.public_outputs_indices { linear_vars[*i] = false; }

        for (a_row, b_row) in r1cs.a_rows.0.iter().zip(r1cs.b_rows.0.iter()) {
            for (i, _a) in &a_row.0 {
                for (j, _b) in &b_row.0 {
                    if i == j {
                        linear_vars[*i] = false;
                    }
                }
            }
        }

        // Search for a pair of variables that don't affect each other, which we can use to solve
        // the two linear equations.
        let mut linear_pair = [0, 0];
        'found: for i in 1..linear_vars.len() {
            if !linear_vars[i] {
                continue
            }
            for j in 0..i {
                if !linear_vars[j] {
                    continue
                }

                // Make sure that they don't affect each other.
                let mut is_linear = true;
                for (a_row, b_row) in r1cs.a_rows.0.iter().zip(r1cs.b_rows.0.iter()) {
                    for (k, _a) in &a_row.0 {
                        for (l, _b) in &b_row.0 {
                            if i == *k && j == *l || i == *l && j == *k {
                                is_linear = false;
                            }
                        }
                    }
                }

                if is_linear {
                    println!("Found linear pair: {}, {}", i, j);
                    linear_pair = [i, j];
                    break 'found;
                }
            }
        }

        if linear_pair[0] == 0 {
            panic!("Could not find a linear pair of variables.");
        }

        // Find the influence of each on the quicksilver constraints.
        let mut qs_influence = [T::from(0); 2];
        for m in 0..2 {
            let i = linear_pair[m];
            for ((a_row, chal), b) in r1cs.a_rows.0.iter().zip(&qs_challenge_vec.0).zip(&u_b.0) {
                for (i1, a) in &a_row.0 {
                    if i == *i1 {
                        qs_influence[m] += *chal * a * b
                    }
                }
            }
            for ((b_row, chal), a) in r1cs.b_rows.0.iter().zip(&qs_challenge_vec.0).zip(&u_a.0) {
                for (i1, b) in &b_row.0 {
                    if i == *i1 {
                        qs_influence[m] += *chal * a * b
                    }
                }
            }
            for (c_row, chal) in r1cs.c_rows.0.iter().zip(&qs_challenge_vec.0) {
                for (i1, c) in &c_row.0 {
                    if i == *i1 {
                        qs_influence[m] -= *chal * c
                    }
                }
            }
        }

        // Find the influence of each on the challenge.
        let chal_influence: Vec<T> = (0..2).map(|m| {
            let i = linear_pair[m];
            let row = i / self.code.k();
            let col = i % self.code.k();
            universal_inner.0[row] * universal_outer.0[col]
        }).collect();

        // Solve the system of linear equations.
        let det = qs_influence[0] * chal_influence[1] - qs_influence[1] * chal_influence[0];
        let inv_det = det.invert().unwrap();
        let witness_changes = [
            inv_det * chal_influence[1] * -qs_error,
            inv_det * -chal_influence[0] * -qs_error,
        ];

        for m in 0..2 {
            let i = linear_pair[m];
            let row = i / self.code.k();
            let col = i % self.code.k();
            self.witness.0[row].0[col] += witness_changes[m];
            witness_comm.0[row].0[col] += witness_changes[m];
        }

        let challenge2 = calc_quicksilver_challenge(seed_comm, &witness_comm);
        assert_eq!(challenge, challenge2);

        // End of actual attack.

        let prover = quicksilver::Prover::from_vith(svs.u1.clone(), svs.u2.clone(), self.witness.clone(), self.circuit.clone());
        let zkp = prover.prove(&challenge);

        let public_openings = PublicOpenings {
            public_inputs: prover.open_public(&self.circuit.public_inputs_indices),
            public_outputs: prover.open_public(&self.circuit.public_outputs_indices)
        };

        let challenges = calc_other_challenges(seed_comm, witness_comm, &zkp, self.vole_length, self.num_voles, &public_openings);
        let (s_matrix, s_consistency_check) = self.s_matrix_with_consistency_proof(&challenges.vith_delta, &challenges.s_challenge)?;


        let mut openings = Vec::with_capacity(self.num_voles);
        let mut opening_proofs = Vec::with_capacity(self.num_voles);
        for i in 0..svs.seeds.len() {
            openings.push(svs.seeds[i][challenges.delta_choices[i]]);
            opening_proofs.push(
                proof_for_revealed_seed(&svs.seeds[i][1 - challenges.delta_choices[i]])
            );
        };

        Ok(
            Proof {
                zkp,
                s_matrix,
                s_consistency_check,
                public_openings,
                seed_openings : SubspaceVOLEOpening { seed_opens: openings, seed_proofs: opening_proofs },
            }
        )
    }

    pub fn commit_and_prove(&mut self) -> Result<CommitAndProof<T>, Error> {
        let mut commitment = self.mkvole()?;
        let proof = self.prove(&mut commitment)?;
        Ok(CommitAndProof { commitment, proof })
    }
}
