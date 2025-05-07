use cfx_vm_types::Spec;

use super::Pricer;

pub trait PricePlan: Send + Sync {
    fn pricer(&self, spec: &Spec) -> &dyn Pricer;
}

pub struct StaticPlan<T: Pricer>(pub T);

impl<T: Pricer> PricePlan for StaticPlan<T> {
    fn pricer(&self, _spec: &Spec) -> &dyn Pricer { &self.0 }
}

pub struct IfPricer<F: Fn(&Spec) -> bool + Send + Sync, T: Pricer, U: Pricer> {
    cond: F,
    true_branch: T,
    false_branch: U,
}

impl<F: Fn(&Spec) -> bool + Send + Sync, T: Pricer, U: Pricer>
    IfPricer<F, T, U>
{
    pub fn new(cond: F, true_branch: T, false_branch: U) -> Self {
        Self {
            cond,
            true_branch,
            false_branch,
        }
    }
}

impl<F: Fn(&Spec) -> bool + Send + Sync, T: Pricer, U: Pricer> PricePlan
    for IfPricer<F, T, U>
{
    fn pricer(&self, spec: &Spec) -> &dyn Pricer {
        if (self.cond)(spec) {
            &self.true_branch
        } else {
            &self.false_branch
        }
    }
}
