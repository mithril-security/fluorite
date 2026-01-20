# Example 

Run at the root of the fluorite repository:

```
sudo ./fluorite-cli/target/debug/fluorite-cli launch-guest --confidential --virtualization-type sev-snp --gpu-setup --network "user,id=vmnic,hostfwd=tcp::9899-:22,hostfwd=tcp::3443-:3443,hostfwd=tcp::6443-:6443,hostfwd=tcp::443-:443,hostfwd=tcp::80-:80"
```