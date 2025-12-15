use typemap::ShareDebugMap;

pub trait DrainTrace {
    fn drain_trace(self, map: &mut ShareDebugMap);
}

impl<T: DrainTrace> DrainTrace for Option<T> {
    fn drain_trace(self, map: &mut ShareDebugMap) {
        if let Some(x) = self {
            x.drain_trace(map);
        }
    }
}

impl DrainTrace for () {
    fn drain_trace(self, _map: &mut ShareDebugMap) {}
}
