use std::sync::{Once, atomic::{AtomicBool, Ordering}};
use std::fs::File;

static INIT_LOGGER: Once = Once::new();
static LOGGER_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init_logger() {
    if !LOGGER_INITIALIZED.load(Ordering::SeqCst) {
        INIT_LOGGER.call_once(|| {
            let mut builder = env_logger::Builder::from_default_env();
            #[cfg(not(test))]
            {
                if let Ok(file) = File::create("rust_core.log") {
                    builder.target(env_logger::Target::Pipe(Box::new(file)));
                }
            }
            builder.filter_level(log::LevelFilter::Debug);
            let _ = builder.try_init();
            LOGGER_INITIALIZED.store(true, Ordering::SeqCst);
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::util::log::init_logger;

    fn test_with_logging() {
        init_logger();
        log::info!("测试开始")
    }
}