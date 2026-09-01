pub fn left(input: u64) -> u64 {
    input + 1
}

pub fn right(input: u64) -> u64 {
    input * 2
}

pub fn top(input: u64) -> u64 {
    left(input) + right(input)
}
