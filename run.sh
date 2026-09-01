# dry-run; no fee; check whether the target matches:
# python3 harness/driver.py --zones specs,aux  --dry-run --path Curve25519Dalek/Specs/Scalar/Scalar --jobs 2 --model claude-sonnet-5 --limit 3

# # real run:
python3 harness/driver.py --zones specs,aux --path Curve25519Dalek/Specs/Scalar/Scalar --jobs 2 --model claude-sonnet-5 --limit 3
