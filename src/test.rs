use crate::assignments::LogupGate;
use ff::PrimeField;
use halo2::circuit::floor_planner::V1;
use halo2::circuit::Value;
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
struct TestConfig<F: PrimeField + Ord, const K: usize> {
    logup_gate: LogupGate<F, K>,
}

#[derive(Debug, Default)]
struct TestCircuit<F: PrimeField + Ord, const K: usize> {
    _marker: PhantomData<F>,
    bit_size: usize,
    number_of_lookups: usize,
}

impl<F: PrimeField + Ord, const K: usize> Circuit<F> for TestCircuit<F, K> {
    type Config = TestConfig<F, K>;
    type FloorPlanner = V1;
    type Params = Params;

    fn without_witnesses(&self) -> Self {
        Self {
            bit_size: self.bit_size,
            number_of_lookups: self.number_of_lookups,
            _marker: PhantomData,
        }
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        let logup_gate = LogupGate::configure(meta, params.bit_size);
        TestConfig { logup_gate }
    }

    fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
        unreachable!()
    }

    fn synthesize(&self, mut cfg: Self::Config, mut ly: impl Layouter<F>) -> Result<(), Error> {
        let table_size = 1 << self.bit_size;

        let w = (0..self.number_of_lookups as u64)
            .map(|_| OsRng.gen_range(0..table_size as u64))
            .collect::<Vec<_>>();

        let w = w.into_iter().map(F::from).collect::<Vec<_>>();

        w.iter()
            .for_each(|w| cfg.logup_gate.lookup(Value::known(*w)));

        cfg.logup_gate.layout(&mut ly)?;

        Ok(())
    }

    fn params(&self) -> Self::Params {
        Params {
            bit_size: self.bit_size,
        }
    }
}

#[test]
fn test_logup() {
    use halo2::halo2curves::pasta::Fq;
    const K: usize = 4;
    let bit_size = 3;

    let circuit = TestCircuit::<Fq, K> {
        _marker: PhantomData,
        bit_size,
        number_of_lookups: 9,
    };
    let public_inputs = vec![];
    let prover = match MockProver::run(K as u32, &circuit, public_inputs) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    prover.assert_satisfied();
}
