mod structs;
mod utils;
mod vector_tests;

pub fn run_tests() {
    vector_tests::tests::test_with_test_vectors();
}
