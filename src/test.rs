use crate::logup::assignments::LogupGate;
use crate::subset::assignments::SubsetGate;
use crate::LookupGate;
use core::num;
use ff::{FromUniformBytes, PrimeField};
use halo2::circuit::{SimpleFloorPlanner, Value};
use halo2::dev::MockProver;
use halo2::{
    circuit::Layouter,
    plonk::Error,
    plonk::{Circuit, ConstraintSystem},
};
use rand::Rng;
use rand_core::OsRng;
use std::marker::PhantomData;

#[derive(Default, Clone, Debug)]
struct Params {
    bit_size: usize,
}

#[derive(Clone, Debug)]
struct TestConfig<F: PrimeField + Ord, Gate: LookupGate<F, W>, const W: usize> {
    gate: Gate,
    _marker: PhantomData<F>,
}

#[derive(Debug, Default)]
struct TestCircuit<F: PrimeField + Ord, Gate: LookupGate<F, W>, const W: usize> {
    _marker: PhantomData<(F, Gate)>,
    bit_size: usize,
    lookups_per_column: usize,
}

impl<F: PrimeField + Ord, Gate: LookupGate<F, W>, const W: usize> Circuit<F>
    for TestCircuit<F, Gate, W>
{
    type Config = TestConfig<F, Gate, W>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = Params;

    fn without_witnesses(&self) -> Self {
        Self {
            bit_size: self.bit_size,
            lookups_per_column: self.lookups_per_column,
            _marker: PhantomData,
        }
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        let gate = Gate::configure(meta, params.bit_size);
        TestConfig {
            gate,
            _marker: PhantomData,
        }
    }

    fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
        unreachable!()
    }

    fn synthesize(&self, mut cfg: Self::Config, mut ly: impl Layouter<F>) -> Result<(), Error> {
        let table_size = 1 << self.bit_size;

        let w = (0..self.lookups_per_column as u64)
            .map(|_| {
                //
                let w: [Value<F>; W] = std::iter::repeat_with(|| {
                    let w = OsRng.gen_range(0..table_size as u64);
                    let w = F::from(w);
                    Value::known(w)
                })
                .take(W)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
                w
            })
            .collect::<Vec<_>>();

        w.iter().for_each(|w| cfg.gate.lookup(w));

        cfg.gate.layout(&mut ly)?;

        Ok(())
    }

    fn params(&self) -> Self::Params {
        Params {
            bit_size: self.bit_size,
        }
    }
}

fn run_test_lookup<F: FromUniformBytes<64> + Ord, Gate: LookupGate<F, W>, const W: usize>(
    k: u32,
    bit_size: usize,
    lookups_per_column: usize,
) {
    let circuit = TestCircuit::<F, Gate, W> {
        _marker: PhantomData,
        bit_size,
        lookups_per_column,
    };
    let public_inputs = vec![];
    let prover = match MockProver::run(k, &circuit, public_inputs) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    prover.assert_satisfied();
}

#[test]
fn test_lookup() {
    use halo2::halo2curves::bn256::Fr;
    run_test_lookup::<Fr, LogupGate<Fr, 10>, 10>(10, 5, 1 << 6);
    run_test_lookup::<Fr, LogupGate<Fr, 10>, 10>(10, 5, 1 << 3);
    run_test_lookup::<Fr, SubsetGate<Fr, 10>, 10>(10, 5, 1 << 6);
    run_test_lookup::<Fr, SubsetGate<Fr, 10>, 10>(10, 5, 1 << 3);
}

mod prover {

    use std::marker::PhantomData;

    use ark_std::{end_timer, start_timer};
    use halo2::halo2curves::bn256::{Bn256, Fr};
    use halo2::plonk::{create_proof, keygen_pk, keygen_vk};
    use halo2::poly::commitment::ParamsProver;
    use halo2::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
    use halo2::poly::kzg::multiopen::ProverSHPLONK;
    use halo2::transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer};
    use rand_core::OsRng;

    use crate::logup::assignments::LogupGate;
    use crate::subset::assignments::SubsetGate;
    use crate::LookupGate;

    use super::TestCircuit;

    fn run_bench_prover<Gate: LookupGate<Fr, W>, const W: usize>(
        desc: &str,
        k: u32,
        bit_size: usize,
        lookups_per_column: usize,
    ) {
        let circuit = TestCircuit::<Fr, Gate, W> {
            _marker: PhantomData,
            bit_size,
            lookups_per_column,
        };

        let params = read_srs(k);
        let vk = keygen_vk(&params, &circuit).unwrap();
        let pk = keygen_pk(&params, vk, &circuit).unwrap();
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        let desc = format!(
            "{desc}, k: {k}, W: {W}, b: {bit_size}, l: {lookups_per_column}, n: {}",
            lookups_per_column * W
        );

        let t0 = start_timer!(|| format!("{desc} prover"));
        let proof = create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<Bn256>, _, _, _, _>(
            &params,
            &pk,
            &[circuit],
            &[&[]],
            OsRng,
            &mut transcript,
        );
        end_timer!(t0);
        proof.expect("proof generation should not fail");
    }

    #[test]
    fn bench_prover() {
        run_bench_prover::<SubsetGate<Fr, 1>, 1>("subset", 17, 16, 1 << 15);
        run_bench_prover::<SubsetGate<Fr, 2>, 2>("subset", 17, 16, 1 << 15);
        run_bench_prover::<SubsetGate<Fr, 3>, 3>("subset", 17, 16, 1 << 15);
        run_bench_prover::<SubsetGate<Fr, 4>, 4>("subset", 17, 16, 1 << 15);
        run_bench_prover::<SubsetGate<Fr, 5>, 5>("subset", 17, 16, 1 << 15);
        run_bench_prover::<SubsetGate<Fr, 6>, 6>("subset", 17, 16, 1 << 15);
        run_bench_prover::<SubsetGate<Fr, 7>, 7>("subset", 17, 16, 1 << 15);
        run_bench_prover::<SubsetGate<Fr, 8>, 8>("subset", 17, 16, 1 << 15);
        run_bench_prover::<SubsetGate<Fr, 9>, 9>("subset", 17, 16, 1 << 15);
        run_bench_prover::<SubsetGate<Fr, 10>, 10>("subset", 17, 16, 1 << 15);

        run_bench_prover::<LogupGate<Fr, 1>, 1>("logup", 17, 16, 1 << 15);
        run_bench_prover::<LogupGate<Fr, 2>, 2>("logup", 17, 16, 1 << 15);
        run_bench_prover::<LogupGate<Fr, 3>, 3>("logup", 17, 16, 1 << 15);
        run_bench_prover::<LogupGate<Fr, 4>, 4>("logup", 17, 16, 1 << 15);
        run_bench_prover::<LogupGate<Fr, 5>, 5>("logup", 17, 16, 1 << 15);
        run_bench_prover::<LogupGate<Fr, 6>, 6>("logup", 17, 16, 1 << 15);
        run_bench_prover::<LogupGate<Fr, 7>, 7>("logup", 17, 16, 1 << 15);
        run_bench_prover::<LogupGate<Fr, 8>, 8>("logup", 17, 16, 1 << 15);
        run_bench_prover::<LogupGate<Fr, 9>, 9>("logup", 17, 16, 1 << 15);
        run_bench_prover::<LogupGate<Fr, 10>, 10>("logup", 17, 16, 1 << 15);
    }

    fn write_srs(k: u32) -> ParamsKZG<Bn256> {
        let path = format!("srs_{k}.bin");
        let params = ParamsKZG::<Bn256>::new(k);
        params
            .write_custom(
                &mut std::fs::File::create(path).unwrap(),
                halo2::SerdeFormat::RawBytesUnchecked,
            )
            .unwrap();
        params
    }

    fn read_srs(k: u32) -> ParamsKZG<Bn256> {
        let path = format!("srs_{k}.bin");
        let file = std::fs::File::open(path.as_str());
        match file {
            Ok(mut file) => {
                ParamsKZG::<Bn256>::read_custom(&mut file, halo2::SerdeFormat::RawBytesUnchecked)
                    .unwrap()
            }
            Err(_) => write_srs(k),
        }
    }
}
