load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "porterhold",
    srcs = ["hold.go"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/shim/v1/extension",
        "//pkg/shim/v1/utils",
        "@com_github_containerd_containerd_api//runtime/task/v2:go_default_library",
        "@com_github_containerd_log//:go_default_library",
    ],
)
