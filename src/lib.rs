pub mod assignments;
pub mod config;
pub mod toy;

use ff::Field;
use halo2::{
    circuit::{AssignedCell, Cell, Region, Value},
    plonk::{Advice, Any, Assigned, Column, Error, Fixed, Selector},
};

pub type AssignedValue<F> = AssignedCell<Assigned<F>, F>;

#[derive(Debug)]
pub struct RegionCtx<'a, F: Field> {
    region: Region<'a, F>,
    offset: usize,
}
impl<'a, F: Field> RegionCtx<'a, F> {
    pub fn new(region: Region<'a, F>) -> RegionCtx<'a, F> {
        RegionCtx { region, offset: 0 }
    }

    pub fn zero(&mut self) {
        self.offset = 0;
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn fixed(&mut self, column: Column<Fixed>, value: F) -> Result<AssignedValue<F>, Error> {
        let value: Assigned<F> = value.into();
        self.region
            .assign_fixed(|| "", column, self.offset, || Value::known(value))
    }

    pub fn advice(
        &mut self,
        column: Column<Advice>,
        value: Value<Assigned<F>>,
    ) -> Result<AssignedValue<F>, Error> {
        self.region
            .assign_advice(|| "", column, self.offset, || value)
    }

    pub fn empty(&mut self, column: Column<Any>) -> Result<AssignedValue<F>, Error> {
        match column.column_type() {
            Any::Advice(_) => self.advice(column.try_into().unwrap(), Value::known(F::ZERO.into())),
            Any::Fixed => self.fixed(column.try_into().unwrap(), F::ZERO),
            _ => panic!("Cannot assign to instance column"),
        }
    }

    pub fn copy(
        &mut self,
        column: Column<Advice>,
        assigned: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        assigned.copy_advice(|| "", &mut self.region, column, self.offset)
    }

    pub fn equal(&mut self, cell_0: Cell, cell_1: Cell) -> Result<(), Error> {
        self.region.constrain_equal(cell_0, cell_1)
    }

    pub fn enable(&mut self, selector: Selector) -> Result<(), Error> {
        selector.enable(&mut self.region, self.offset)
    }

    pub fn next(&mut self) {
        self.offset += 1
    }
}
