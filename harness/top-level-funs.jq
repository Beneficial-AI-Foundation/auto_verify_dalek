# jq -r --arg file "Curve25519Dalek/Funs.lean" -f harness/top-level-funs.jq lean_extract.json
.data as $atoms
| [ $atoms | to_entries[] | select(.value["code-path"] == $file) ] as $funs
| ( [ $funs[] | select((.value.attributes // []) | index("reducible"))
              | {key: .key, value: true} ] | from_entries ) as $rec
| ( [ $funs[] | select((.value.attributes // []) | index("rust_loop"))
              | {key: .key, value: true} ] | from_entries ) as $loop
| ( [ $funs[] | .key | select($rec[.] != true and $loop[.] != true)
              | {key: ., value: true} ] | from_entries ) as $cand
# a record is transparent: replace it by its own dependencies, repeatedly.
# bounded, so a cyclic supertrait graph terminates instead of spinning.
| def thru:
    reduce range(0; 8) as $_ (.;
      [ .[] | if $rec[.] == true
              then ((($atoms[.] // {}).dependencies // [])[])
              else . end ] | unique);
  ( [ $funs[]
      | select($rec[.key] != true)
      | (if $loop[.key] == true then (.key | sub("_loop$"; "")) else .key end) as $src
      | select($cand[$src] == true)
      | ((.value.dependencies // []) | thru)[]
      | select($cand[.] == true and . != $src)
    ] | unique ) as $referenced
| [ $cand | keys[] ] - $referenced | sort[]
