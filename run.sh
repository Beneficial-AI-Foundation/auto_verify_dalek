# dry-run; no fee; check whether the target matches:
# python3 harness/driver.py --zones specs,aux  --dry-run --path Curve25519Dalek/Specs/Scalar/Scalar --jobs 2 --model claude-sonnet-5 --limit 3

# # real run. DEC-20: the checkout is already comment-free (preprocessing step,
# # `harness/strip_comments.py strip --in-place`; last commented tree: commit 66753cb),
# # so no --strip-comments flag is needed here.
python3 harness/driver.py --zones specs,aux --path Curve25519Dalek/Specs/Scalar/Scalar --jobs 2 --model claude-sonnet-5 --limit 3
