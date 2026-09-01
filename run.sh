# dry-run; no fee; check whether the target matches:
python3 harness/driver.py --zones specs,aux --match Scalar --dry-run --model claude-sonnet-5

# # real run:
# python3 harness/driver.py --zones specs,aux --match Scalar --jobs 2 --model claude-sonnet-5
