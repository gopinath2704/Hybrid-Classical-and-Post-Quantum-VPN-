# Ubuntu 26.04 may add IPv6 link-local routes for newly created veth devices
# asynchronously.  Exclude only those volatile, kernel-generated fe80:: records;
# manually managed link-local routes and every non-link-local route remain part of
# the namespace harness's before/after comparison.
{
    destination = $1
    # Local-table records can begin with a route type (for example, "local"
    # or "anycast") rather than the destination itself.
    if (destination !~ /:/ && $2 ~ /:/) {
        destination = $2
    }
    kernel_generated = 0
    for (field = 1; field < NF; field++) {
        if ($field == "proto" && $(field + 1) == "kernel") {
            kernel_generated = 1
            break
        }
    }
    if (destination ~ /^fe80:/ && kernel_generated) {
        next
    }
    print
}
