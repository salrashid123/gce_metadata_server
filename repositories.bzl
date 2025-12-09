load("@gazelle//:deps.bzl", "go_repository")

def go_repositories():
    go_repository(
        name = "com_github_alecthomas_kingpin_v2",
        importpath = "github.com/alecthomas/kingpin/v2",
        sum = "h1:f48lwail6p8zpO1bC4TxtqACaGqHYA22qkHjHpqDjYY=",
        version = "v2.4.0",
    )
    go_repository(
        name = "com_github_alecthomas_units",
        importpath = "github.com/alecthomas/units",
        sum = "h1:mimo19zliBX/vSQ6PWWSL9lK8qwHozUj03+zLoEB8O0=",
        version = "v0.0.0-20240927000941-0f3dac36c52b",
    )
    go_repository(
        name = "com_github_beorn7_perks",
        importpath = "github.com/beorn7/perks",
        sum = "h1:VlbKKnNfV8bJzeqoa4cOKqO6bYr3WgKZxO8Z16+hsOM=",
        version = "v1.0.1",
    )
    go_repository(
        name = "com_github_cespare_xxhash_v2",
        importpath = "github.com/cespare/xxhash/v2",
        sum = "h1:UL815xU9SqsFlibzuggzjXhog7bL6oX9BbNZnL2UFvs=",
        version = "v2.3.0",
    )
    go_repository(
        name = "com_github_cncf_xds_go",
        importpath = "github.com/cncf/xds/go",
        sum = "h1:Y8xYupdHxryycyPlc9Y+bSQAYZnetRJ70VMVKm5CKI0=",
        version = "v0.0.0-20251022180443-0feb69152e9f",
    )
    go_repository(
        name = "com_github_davecgh_go_spew",
        importpath = "github.com/davecgh/go-spew",
        sum = "h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=",
        version = "v1.1.1",
    )
    go_repository(
        name = "com_github_envoyproxy_go_control_plane",
        importpath = "github.com/envoyproxy/go-control-plane",
        sum = "h1:K+fnvUM0VZ7ZFJf0n4L/BRlnsb9pL/GuDG6FqaH+PwM=",
        version = "v0.13.5-0.20251024222203-75eaa193e329",
    )
    go_repository(
        name = "com_github_envoyproxy_go_control_plane_envoy",
        importpath = "github.com/envoyproxy/go-control-plane/envoy",
        sum = "h1:ixjkELDE+ru6idPxcHLj8LBVc2bFP7iBytj353BoHUo=",
        version = "v1.35.0",
    )
    go_repository(
        name = "com_github_envoyproxy_go_control_plane_ratelimit",
        importpath = "github.com/envoyproxy/go-control-plane/ratelimit",
        sum = "h1:/G9QYbddjL25KvtKTv3an9lx6VBE2cnb8wp1vEGNYGI=",
        version = "v0.1.0",
    )
    go_repository(
        name = "com_github_envoyproxy_protoc_gen_validate",
        importpath = "github.com/envoyproxy/protoc-gen-validate",
        sum = "h1:DEo3O99U8j4hBFwbJfrz9VtgcDfUKS7KJ7spH3d86P8=",
        version = "v1.2.1",
    )
    go_repository(
        name = "com_github_felixge_httpsnoop",
        importpath = "github.com/felixge/httpsnoop",
        sum = "h1:NFTV2Zj1bL4mc9sqWACXbQFVBBg2W3GPvqp8/ESS2Wg=",
        version = "v1.0.4",
    )
    go_repository(
        name = "com_github_foxboron_go_tpm_keyfiles",
        importpath = "github.com/foxboron/go-tpm-keyfiles",
        sum = "h1:EdO/NMMuCZfxhdzTZLuKAciQSnI2DV+Ppg8+vAYrnqA=",
        version = "v0.0.0-20250903184740-5d135037bd4d",
    )
    go_repository(
        name = "com_github_foxboron_swtpm_test",
        importpath = "github.com/foxboron/swtpm_test",
        sum = "h1:50sW4r0PcvlpG4PV8tYh2RVCapszJgaOLRCS2subvV4=",
        version = "v0.0.0-20230726224112-46aaafdf7006",
    )
    go_repository(
        name = "com_github_fsnotify_fsnotify",
        importpath = "github.com/fsnotify/fsnotify",
        sum = "h1:2Ml+OJNzbYCTzsxtv8vKSFD9PbJjmhYF14k/jKC7S9k=",
        version = "v1.9.0",
    )
    go_repository(
        name = "com_github_go_jose_go_jose_v4",
        importpath = "github.com/go-jose/go-jose/v4",
        sum = "h1:CVLmWDhDVRa6Mi/IgCgaopNosCaHz7zrMeF9MlZRkrs=",
        version = "v4.1.3",
    )
    go_repository(
        name = "com_github_go_logr_logr",
        importpath = "github.com/go-logr/logr",
        sum = "h1:CjnDlHq8ikf6E492q6eKboGOC0T8CDaOvkHCIg8idEI=",
        version = "v1.4.3",
    )
    go_repository(
        name = "com_github_go_logr_stdr",
        importpath = "github.com/go-logr/stdr",
        sum = "h1:hSWxHoqTgW2S2qGc0LTAI563KZ5YKYRhT3MFKZMbjag=",
        version = "v1.2.2",
    )
    go_repository(
        name = "com_github_golang_glog",
        importpath = "github.com/golang/glog",
        sum = "h1:DrW6hGnjIhtvhOIiAKT6Psh/Kd/ldepEa81DKeiRJ5I=",
        version = "v1.2.5",
    )
    go_repository(
        name = "com_github_golang_groupcache",
        importpath = "github.com/golang/groupcache",
        sum = "h1:oI5xCqsCo564l8iNU+DwB5epxmsaqB+rhGL0m5jtYqE=",
        version = "v0.0.0-20210331224755-41bb18bfe9da",
    )
    go_repository(
        name = "com_github_golang_jwt_jwt_v5",
        importpath = "github.com/golang-jwt/jwt/v5",
        sum = "h1:pv4AsKCKKZuqlgs5sUmn4x8UlGa0kEVt/puTpKx9vvo=",
        version = "v5.3.0",
    )
    go_repository(
        name = "com_github_golang_protobuf",
        importpath = "github.com/golang/protobuf",
        sum = "h1:i7eJL8qZTpSEXOPTxNKhASYpMn+8e5Q6AdndVa1dWek=",
        version = "v1.5.4",
    )
    go_repository(
        name = "com_github_google_go_cmp",
        importpath = "github.com/google/go-cmp",
        sum = "h1:wk8382ETsv4JYUZwIsn6YpYiWiBsYLSJiTsyBybVuN8=",
        version = "v0.7.0",
    )
    go_repository(
        name = "com_github_google_go_configfs_tsm",
        importpath = "github.com/google/go-configfs-tsm",
        sum = "h1:YnJ9rXIOj5BYD7/0DNnzs8AOp7UcvjfTvt215EWcs98=",
        version = "v0.2.2",
    )
    go_repository(
        name = "com_github_google_go_pkcs11",
        importpath = "github.com/google/go-pkcs11",
        sum = "h1:PVRnTgtArZ3QQqTGtbtjtnIkzl2iY2kt24yqbrf7td8=",
        version = "v0.3.0",
    )
    go_repository(
        name = "com_github_google_go_tpm",
        importpath = "github.com/google/go-tpm",
        sum = "h1:u89J4tUUeDTlH8xxC3CTW7OHZjbjKoHdQ9W7gCUhtxA=",
        version = "v0.9.7",
    )
    go_repository(
        name = "com_github_google_go_tpm_tools",
        importpath = "github.com/google/go-tpm-tools",
        sum = "h1:3fhthtyMDbIZFR5/0y1hvUoZ1Kf4i1eZ7C73R4Pvd+k=",
        version = "v0.4.5",
    )
    go_repository(
        name = "com_github_google_s2a_go",
        importpath = "github.com/google/s2a-go",
        sum = "h1:LGD7gtMgezd8a/Xak7mEWL0PjoTQFvpRudN895yqKW0=",
        version = "v0.1.9",
    )
    go_repository(
        name = "com_github_google_uuid",
        importpath = "github.com/google/uuid",
        sum = "h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=",
        version = "v1.6.0",
    )
    go_repository(
        name = "com_github_googleapis_enterprise_certificate_proxy",
        importpath = "github.com/googleapis/enterprise-certificate-proxy",
        sum = "h1:zrn2Ee/nWmHulBx5sAVrGgAa0f2/R35S4DJwfFaUPFQ=",
        version = "v0.3.7",
    )
    go_repository(
        name = "com_github_googleapis_gax_go_v2",
        importpath = "github.com/googleapis/gax-go/v2",
        sum = "h1:SyjDc1mGgZU5LncH8gimWo9lW1DtIfPibOG81vgd/bo=",
        version = "v2.15.0",
    )
    go_repository(
        name = "com_github_googlecloudplatform_opentelemetry_operations_go_detectors_gcp",
        importpath = "github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp",
        sum = "h1:sBEjpZlNHzK1voKq9695PJSX2o5NEXl7/OL3coiIY0c=",
        version = "v1.30.0",
    )
    go_repository(
        name = "com_github_gorilla_mux",
        importpath = "github.com/gorilla/mux",
        sum = "h1:TuBL49tXwgrFYWhqrNgrUNEY92u81SPhu7sTdzQEiWY=",
        version = "v1.8.1",
    )
    go_repository(
        name = "com_github_jpillora_backoff",
        importpath = "github.com/jpillora/backoff",
        sum = "h1:uvFg412JmmHBHw7iwprIxkPMI+sGQ4kzOWsMeHnm2EA=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_json_iterator_go",
        importpath = "github.com/json-iterator/go",
        sum = "h1:PV8peI4a0ysnczrg+LtxykD8LfKY9ML6u2jnxaEnrnM=",
        version = "v1.1.12",
    )
    go_repository(
        name = "com_github_julienschmidt_httprouter",
        importpath = "github.com/julienschmidt/httprouter",
        sum = "h1:U0609e9tgbseu3rBINet9P48AI/D3oJs4dN7jwJOQ1U=",
        version = "v1.3.0",
    )
    go_repository(
        name = "com_github_klauspost_compress",
        importpath = "github.com/klauspost/compress",
        sum = "h1:c/Cqfb0r+Yi+JtIEq73FWXVkRonBlf0CRNYc8Zttxdo=",
        version = "v1.18.0",
    )
    go_repository(
        name = "com_github_kr_pretty",
        importpath = "github.com/kr/pretty",
        sum = "h1:flRD4NNwYAUpkphVc1HcthR4KEIFJ65n8Mw5qdRn3LE=",
        version = "v0.3.1",
    )
    go_repository(
        name = "com_github_kr_text",
        importpath = "github.com/kr/text",
        sum = "h1:5Nx0Ya0ZqY2ygV366QzturHI13Jq95ApcVaJBhpS+AY=",
        version = "v0.2.0",
    )
    go_repository(
        name = "com_github_kylelemons_godebug",
        importpath = "github.com/kylelemons/godebug",
        sum = "h1:RPNrshWIDI6G2gRW9EHilWtl7Z6Sb1BR0xunSBf0SNc=",
        version = "v1.1.0",
    )
    go_repository(
        name = "com_github_modern_go_concurrent",
        importpath = "github.com/modern-go/concurrent",
        sum = "h1:TRLaZ9cD/w8PVh93nsPXa1VrQ6jlwL5oN8l14QlcNfg=",
        version = "v0.0.0-20180306012644-bacd9c7ef1dd",
    )
    go_repository(
        name = "com_github_modern_go_reflect2",
        importpath = "github.com/modern-go/reflect2",
        sum = "h1:xBagoLtFs94CBntxluKeaWgTMpvLxC4ur3nMaC9Gz0M=",
        version = "v1.0.2",
    )
    go_repository(
        name = "com_github_munnerz_goautoneg",
        importpath = "github.com/munnerz/goautoneg",
        sum = "h1:C3w9PqII01/Oq1c1nUAm88MOHcQC9l5mIlSMApZMrHA=",
        version = "v0.0.0-20191010083416-a7dc8b61c822",
    )
    go_repository(
        name = "com_github_mwitkow_go_conntrack",
        importpath = "github.com/mwitkow/go-conntrack",
        sum = "h1:KUppIJq7/+SVif2QVs3tOP0zanoHgBEVAwHxUSIzRqU=",
        version = "v0.0.0-20190716064945-2f068394615f",
    )
    go_repository(
        name = "com_github_planetscale_vtprotobuf",
        importpath = "github.com/planetscale/vtprotobuf",
        sum = "h1:GFCKgmp0tecUJ0sJuv4pzYCqS9+RGSn52M3FUwPs+uo=",
        version = "v0.6.1-0.20240319094008-0393e58bdf10",
    )
    go_repository(
        name = "com_github_pmezard_go_difflib",
        importpath = "github.com/pmezard/go-difflib",
        sum = "h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_prometheus_client_golang",
        importpath = "github.com/prometheus/client_golang",
        sum = "h1:Je96obch5RDVy3FDMndoUsjAhG5Edi49h0RJWRi/o0o=",
        version = "v1.23.2",
    )
    go_repository(
        name = "com_github_prometheus_client_model",
        importpath = "github.com/prometheus/client_model",
        sum = "h1:oBsgwpGs7iVziMvrGhE53c/GrLUsZdHnqNwqPLxwZyk=",
        version = "v0.6.2",
    )
    go_repository(
        name = "com_github_prometheus_common",
        importpath = "github.com/prometheus/common",
        sum = "h1:yR3NqWO1/UyO1w2PhUvXlGQs/PtFmoveVO0KZ4+Lvsc=",
        version = "v0.67.4",
    )
    go_repository(
        name = "com_github_prometheus_procfs",
        importpath = "github.com/prometheus/procfs",
        sum = "h1:zUMhqEW66Ex7OXIiDkll3tl9a1ZdilUOd/F6ZXw4Vws=",
        version = "v0.19.2",
    )
    go_repository(
        name = "com_github_rogpeppe_go_internal",
        importpath = "github.com/rogpeppe/go-internal",
        sum = "h1:UQB4HGPB6osV0SQTLymcB4TgvyWu6ZyliaW0tI/otEQ=",
        version = "v1.14.1",
    )
    go_repository(
        name = "com_github_salrashid123_golang_jwt_tpm",
        importpath = "github.com/salrashid123/golang-jwt-tpm",
        sum = "h1:bux56qLDmFTWStiIkDQhR3j/7UhnbVIP0yr2458mX0U=",
        version = "v1.8.97",
    )
    go_repository(
        name = "com_github_salrashid123_mtls_tokensource_tpm",
        importpath = "github.com/salrashid123/mtls-tokensource/tpm",
        sum = "h1:vRVQEwt1M0yNtfHnOgzaIGHTaAjvfO542uVamZRYfow=",
        version = "v0.0.60",
    )
    go_repository(
        name = "com_github_salrashid123_oauth2_v3",
        importpath = "github.com/salrashid123/oauth2/v3",
        sum = "h1:UkpiBylD8JoBZD1h5bEUzVMr5B3b1Xz2PLtw5exATEY=",
        version = "v3.0.9",
    )
    go_repository(
        name = "com_github_salrashid123_tpmsigner",
        importpath = "github.com/salrashid123/tpmsigner",
        sum = "h1:0w87pjk5ReJ4CON99gIYBajJN2KTjoAAqFjOypcmQ3U=",
        version = "v0.9.82",
    )
    go_repository(
        name = "com_github_spiffe_go_spiffe_v2",
        importpath = "github.com/spiffe/go-spiffe/v2",
        sum = "h1:l+DolpxNWYgruGQVV0xsfeya3CsC7m8iBzDnMpsbLuo=",
        version = "v2.6.0",
    )
    go_repository(
        name = "com_github_stretchr_testify",
        importpath = "github.com/stretchr/testify",
        sum = "h1:7s2iGBzp5EwR7/aIZr8ao5+dra3wiQyKjjFuvgVKu7U=",
        version = "v1.11.1",
    )
    go_repository(
        name = "com_github_xhit_go_str2duration_v2",
        importpath = "github.com/xhit/go-str2duration/v2",
        sum = "h1:lxklc02Drh6ynqX+DdPyp5pCKLUQpRT8bp8Ydu2Bstc=",
        version = "v2.1.0",
    )
    go_repository(
        name = "com_google_cloud_go",
        importpath = "cloud.google.com/go",
        sum = "h1:waZiuajrI28iAf40cWgycWNgaXPO06dupuS+sgibK6c=",
        version = "v0.121.6",
    )
    go_repository(
        name = "com_google_cloud_go_accessapproval",
        importpath = "cloud.google.com/go/accessapproval",
        sum = "h1:gq8OS+rQWgGRo91D2qztN+ion6AZ2T1CxBIu0ifCmVo=",
        version = "v1.8.8",
    )
    go_repository(
        name = "com_google_cloud_go_accesscontextmanager",
        importpath = "cloud.google.com/go/accesscontextmanager",
        sum = "h1:aKIfg7Jyc73pe8bzx0zypNdS5gfFdSvFvB8YNA9k2kA=",
        version = "v1.9.7",
    )
    go_repository(
        name = "com_google_cloud_go_aiplatform",
        importpath = "cloud.google.com/go/aiplatform",
        sum = "h1:A1on/tr2Y7EwhW4M1dtuVMWioxFD5oiacZ85MOi9HH8=",
        version = "v1.109.0",
    )
    go_repository(
        name = "com_google_cloud_go_analytics",
        importpath = "cloud.google.com/go/analytics",
        sum = "h1:souLxu9tQHzF+0NDpKoIw4pl2WQ9K2JfkdPPs36BfXw=",
        version = "v0.30.1",
    )
    go_repository(
        name = "com_google_cloud_go_apigateway",
        importpath = "cloud.google.com/go/apigateway",
        sum = "h1:ehKUTy+QFsb3n07fEi18S2dpDDjCV4UlRyrbwfZV3Zk=",
        version = "v1.7.7",
    )
    go_repository(
        name = "com_google_cloud_go_apigeeconnect",
        importpath = "cloud.google.com/go/apigeeconnect",
        sum = "h1:S6s2zojwMymx0fyZYKm0eK1TdDxrriIBAlNVvRAOzug=",
        version = "v1.7.7",
    )
    go_repository(
        name = "com_google_cloud_go_apigeeregistry",
        importpath = "cloud.google.com/go/apigeeregistry",
        sum = "h1:QziFVsuPU2lhy40Ht9uWEyciV23SH9GETWiwcu3qzdg=",
        version = "v0.10.0",
    )
    go_repository(
        name = "com_google_cloud_go_appengine",
        importpath = "cloud.google.com/go/appengine",
        sum = "h1:IxGz6j5xv0nTJX285wu95Vn6KEi2CeV9vbyRgCSEAoU=",
        version = "v1.9.7",
    )
    go_repository(
        name = "com_google_cloud_go_area120",
        importpath = "cloud.google.com/go/area120",
        sum = "h1:BbpzLwaIXVPorrrzTH+ni7P5mLemmPPfSZ7o39k7zQc=",
        version = "v0.9.7",
    )
    go_repository(
        name = "com_google_cloud_go_artifactregistry",
        importpath = "cloud.google.com/go/artifactregistry",
        sum = "h1:Gx5vsnIFEx+obM1VdtMF2AuTraYESRCrBxvc9+6jBZg=",
        version = "v1.17.2",
    )
    go_repository(
        name = "com_google_cloud_go_asset",
        importpath = "cloud.google.com/go/asset",
        sum = "h1:81Ru5hjHfiGtk+u/Ix69eaWieKpvm7Ce7UHtcZhOLbk=",
        version = "v1.22.0",
    )
    go_repository(
        name = "com_google_cloud_go_assuredworkloads",
        importpath = "cloud.google.com/go/assuredworkloads",
        sum = "h1:NQXyyGLksPmiapE1Oc64a3cMwYIBAoDBg6cWR+B3eaY=",
        version = "v1.13.0",
    )
    go_repository(
        name = "com_google_cloud_go_auth",
        importpath = "cloud.google.com/go/auth",
        sum = "h1:74yCm7hCj2rUyyAocqnFzsAYXgJhrG26XCFimrc/Kz4=",
        version = "v0.17.0",
    )
    go_repository(
        name = "com_google_cloud_go_auth_oauth2adapt",
        importpath = "cloud.google.com/go/auth/oauth2adapt",
        sum = "h1:keo8NaayQZ6wimpNSmW5OPc283g65QNIiLpZnkHRbnc=",
        version = "v0.2.8",
    )
    go_repository(
        name = "com_google_cloud_go_automl",
        importpath = "cloud.google.com/go/automl",
        sum = "h1:YRwLbsBv4yApX64pkrdyy4emhWE6lHEnljX4b1aTQC4=",
        version = "v1.15.0",
    )
    go_repository(
        name = "com_google_cloud_go_baremetalsolution",
        importpath = "cloud.google.com/go/baremetalsolution",
        sum = "h1:g67fjVdrNCHZl8jDWdZvo+6zGTTMMuvNWO7HSgG8lnI=",
        version = "v1.4.0",
    )
    go_repository(
        name = "com_google_cloud_go_batch",
        importpath = "cloud.google.com/go/batch",
        sum = "h1:6gmnNhJhm+Y598CZE6x+CeNZNIPCkYa4vkF58S5abHo=",
        version = "v1.13.0",
    )
    go_repository(
        name = "com_google_cloud_go_beyondcorp",
        importpath = "cloud.google.com/go/beyondcorp",
        sum = "h1:mre997ya7QHFWSU+O5cT/FhBKTMy6Riqf1EXFxN46zw=",
        version = "v1.2.0",
    )
    go_repository(
        name = "com_google_cloud_go_bigquery",
        importpath = "cloud.google.com/go/bigquery",
        sum = "h1:D/yLju+3Ens2IXx7ou1DJ62juBm+/coBInn4VVOg5Cw=",
        version = "v1.72.0",
    )
    go_repository(
        name = "com_google_cloud_go_bigtable",
        importpath = "cloud.google.com/go/bigtable",
        sum = "h1:k8HfpUOvn7sQwc6oNKqjvD/yjkwynf4qBuyKwh5cU08=",
        version = "v1.40.1",
    )
    go_repository(
        name = "com_google_cloud_go_billing",
        importpath = "cloud.google.com/go/billing",
        sum = "h1:nbQjTXkpgB/E4XnYZQwcZnR63QFsbFwJ9DGsNg61Ghg=",
        version = "v1.21.0",
    )
    go_repository(
        name = "com_google_cloud_go_binaryauthorization",
        importpath = "cloud.google.com/go/binaryauthorization",
        sum = "h1:YYK0BwiZv9uA6z+Ict908AykX4OBfDECMTE476OnS3A=",
        version = "v1.10.0",
    )
    go_repository(
        name = "com_google_cloud_go_certificatemanager",
        importpath = "cloud.google.com/go/certificatemanager",
        sum = "h1:v5X8X+THKrS9OFZb6k0GRDP1WQxLXTdMko7OInBliw4=",
        version = "v1.9.6",
    )
    go_repository(
        name = "com_google_cloud_go_channel",
        importpath = "cloud.google.com/go/channel",
        sum = "h1:EeUa6SnD3+EL9B06G6N9Ud5/p/NtT6PC7lv5kmaUiHs=",
        version = "v1.20.0",
    )
    go_repository(
        name = "com_google_cloud_go_cloudbuild",
        importpath = "cloud.google.com/go/cloudbuild",
        sum = "h1:Kl4QBrOPXcHVTic6XeRMp9YgLCy3b/ifGx8i29A3pYs=",
        version = "v1.23.1",
    )
    go_repository(
        name = "com_google_cloud_go_clouddms",
        importpath = "cloud.google.com/go/clouddms",
        sum = "h1:YWsmRXTyK6Ba0hm4qTBak5g1oLhryuM8rSBxHWC8iq4=",
        version = "v1.8.8",
    )
    go_repository(
        name = "com_google_cloud_go_cloudtasks",
        importpath = "cloud.google.com/go/cloudtasks",
        sum = "h1:H2v8GEolNtMFfYzUpZBaZbydqU7drpyo99GtAgA+m4I=",
        version = "v1.13.7",
    )
    go_repository(
        name = "com_google_cloud_go_compute",
        importpath = "cloud.google.com/go/compute",
        sum = "h1:KYKIG0+pfpAWaAYayFkE/KPrAVCge0Hu82bPraAmsCk=",
        version = "v1.49.1",
    )
    go_repository(
        name = "com_google_cloud_go_compute_metadata",
        importpath = "cloud.google.com/go/compute/metadata",
        sum = "h1:pDUj4QMoPejqq20dK0Pg2N4yG9zIkYGdBtwLoEkH9Zs=",
        version = "v0.9.0",
    )
    go_repository(
        name = "com_google_cloud_go_contactcenterinsights",
        importpath = "cloud.google.com/go/contactcenterinsights",
        sum = "h1:wA4j99BhsoeYlLx6xEIqrNN1aOTtUme0wimHZegg80s=",
        version = "v1.17.4",
    )
    go_repository(
        name = "com_google_cloud_go_container",
        importpath = "cloud.google.com/go/container",
        sum = "h1:i1No5obpPxlIFLGHdUF6h2YjRR1qN9t/ZkA8KA5B//o=",
        version = "v1.45.0",
    )
    go_repository(
        name = "com_google_cloud_go_containeranalysis",
        importpath = "cloud.google.com/go/containeranalysis",
        sum = "h1:OW2dlMPtR5VnjQGyAP+uJlZahc1l+JFxFlH/J3+l7gw=",
        version = "v0.14.2",
    )
    go_repository(
        name = "com_google_cloud_go_datacatalog",
        importpath = "cloud.google.com/go/datacatalog",
        sum = "h1:bCRKA8uSQN8wGW3Tw0gwko4E9a64GRmbW1nCblhgC2k=",
        version = "v1.26.1",
    )
    go_repository(
        name = "com_google_cloud_go_dataflow",
        importpath = "cloud.google.com/go/dataflow",
        sum = "h1:Z+UYlGrE+IoB+5IAN4/qWdPKO0IpIK9bs2Dy40HK6lg=",
        version = "v0.11.1",
    )
    go_repository(
        name = "com_google_cloud_go_dataform",
        importpath = "cloud.google.com/go/dataform",
        sum = "h1:yf6Up6m1FUt+YB5CBgNtIZfz2OzjuNBdzZWV3SLSVNE=",
        version = "v0.12.1",
    )
    go_repository(
        name = "com_google_cloud_go_datafusion",
        importpath = "cloud.google.com/go/datafusion",
        sum = "h1:tLCV+xYuOrSjdrRTkc9Cqsb5mBSQEsNfFmuTNYl5/rA=",
        version = "v1.8.7",
    )
    go_repository(
        name = "com_google_cloud_go_datalabeling",
        importpath = "cloud.google.com/go/datalabeling",
        sum = "h1:wwoct7mw38s75XvEmLoItQ2TY0RFsGiRDb0iNbXUcX4=",
        version = "v0.9.7",
    )
    go_repository(
        name = "com_google_cloud_go_dataplex",
        importpath = "cloud.google.com/go/dataplex",
        sum = "h1:rROI3iqMVI9nXT701ULoFRETQVAOAPC3mPSWFDxXFl0=",
        version = "v1.28.0",
    )
    go_repository(
        name = "com_google_cloud_go_dataproc_v2",
        importpath = "cloud.google.com/go/dataproc/v2",
        sum = "h1:I/Yux/d8uaxf3W+d59kolGTOc52+VZaL6RzJw7oDOeg=",
        version = "v2.15.0",
    )
    go_repository(
        name = "com_google_cloud_go_dataqna",
        importpath = "cloud.google.com/go/dataqna",
        sum = "h1:3FREvU+sjaEHSjlKrKF6KjUmafdOvM8CbZ897rttxNs=",
        version = "v0.9.8",
    )
    go_repository(
        name = "com_google_cloud_go_datastore",
        importpath = "cloud.google.com/go/datastore",
        sum = "h1:dUrYq47ysCA4nM7u8kRT0WnbfXc6TzX49cP3TCwIiA0=",
        version = "v1.21.0",
    )
    go_repository(
        name = "com_google_cloud_go_datastream",
        importpath = "cloud.google.com/go/datastream",
        sum = "h1:7PKeDpksi8nbOR4gspmNokzsr0q/uRzDIt20bR3BtRs=",
        version = "v1.15.1",
    )
    go_repository(
        name = "com_google_cloud_go_deploy",
        importpath = "cloud.google.com/go/deploy",
        sum = "h1:QU8gLXsXDRqLyEWNrI6zJiVzuuOBX/WpMi4p0oexV+c=",
        version = "v1.27.3",
    )
    go_repository(
        name = "com_google_cloud_go_dialogflow",
        importpath = "cloud.google.com/go/dialogflow",
        sum = "h1:P2VLpdyxu1gxsocyVWGfLzxvZ8Esxh2KULHhNuZ3FXI=",
        version = "v1.71.0",
    )
    go_repository(
        name = "com_google_cloud_go_dlp",
        importpath = "cloud.google.com/go/dlp",
        sum = "h1:rBQCAcIdWxyLRbFsOkyLig0OFhcKhCThtnro+b3dvEc=",
        version = "v1.27.0",
    )
    go_repository(
        name = "com_google_cloud_go_documentai",
        importpath = "cloud.google.com/go/documentai",
        sum = "h1:ngPNmVUb3xxj6/j7ruK4vmOMm+XTJO0Vi7Jkm0R3AdU=",
        version = "v1.39.0",
    )
    go_repository(
        name = "com_google_cloud_go_domains",
        importpath = "cloud.google.com/go/domains",
        sum = "h1:G3kUq0vKBMhyOj5GqAfEYbVuez05U+ENHZUAtrEp/pI=",
        version = "v0.10.7",
    )
    go_repository(
        name = "com_google_cloud_go_edgecontainer",
        importpath = "cloud.google.com/go/edgecontainer",
        sum = "h1:6KTQo6Qf0iEtfPVotlG7orazEO1I93Ham0PMlkHYpdQ=",
        version = "v1.4.4",
    )
    go_repository(
        name = "com_google_cloud_go_errorreporting",
        importpath = "cloud.google.com/go/errorreporting",
        sum = "h1:isaoPwWX8kbAOea4qahcmttoS79+gQhvKsfg5L5AgH8=",
        version = "v0.3.2",
    )
    go_repository(
        name = "com_google_cloud_go_essentialcontacts",
        importpath = "cloud.google.com/go/essentialcontacts",
        sum = "h1:v9sO4IHFuwplaOuDnEXZFtfOrjw2bi11TSIVp5PnAU4=",
        version = "v1.7.7",
    )
    go_repository(
        name = "com_google_cloud_go_eventarc",
        importpath = "cloud.google.com/go/eventarc",
        sum = "h1:cog4hh0RNbVC7KVwibCqBPhBKklj4wnIJVz8Qrf2hVI=",
        version = "v1.17.0",
    )
    go_repository(
        name = "com_google_cloud_go_filestore",
        importpath = "cloud.google.com/go/filestore",
        sum = "h1:3KZifUVTqGhNNv6MLeONYth1HjlVM4vDhaH+xrdPljU=",
        version = "v1.10.3",
    )
    go_repository(
        name = "com_google_cloud_go_firestore",
        importpath = "cloud.google.com/go/firestore",
        sum = "h1:JLlT12QP0fM2SJirKVyu2spBCO8leElaW0OOtPm6HEo=",
        version = "v1.20.0",
    )
    go_repository(
        name = "com_google_cloud_go_functions",
        importpath = "cloud.google.com/go/functions",
        sum = "h1:7LcOD18euIVGRUPaeCmgO6vfWSLNIsi6STWRQcdANG8=",
        version = "v1.19.7",
    )
    go_repository(
        name = "com_google_cloud_go_gkebackup",
        importpath = "cloud.google.com/go/gkebackup",
        sum = "h1:gUgI3lZJYALZsHXE7YJOKI8bMpoAX/tF6jnNugvzT1g=",
        version = "v1.8.1",
    )
    go_repository(
        name = "com_google_cloud_go_gkeconnect",
        importpath = "cloud.google.com/go/gkeconnect",
        sum = "h1:EFql3zRaFw74yATt5lf+mcPDqPZ4EeLvoIJ+0NaEkag=",
        version = "v0.12.5",
    )
    go_repository(
        name = "com_google_cloud_go_gkehub",
        importpath = "cloud.google.com/go/gkehub",
        sum = "h1:Jk5pAXG54FlQzTRXhuKyym/NzOgS8oWRs0XNatZYDf4=",
        version = "v0.16.0",
    )
    go_repository(
        name = "com_google_cloud_go_gkemulticloud",
        importpath = "cloud.google.com/go/gkemulticloud",
        sum = "h1:AKuOmr5QBCPLJCyZhBABP3lIz+h3jxAy53LVMrEuvlg=",
        version = "v1.5.4",
    )
    go_repository(
        name = "com_google_cloud_go_gsuiteaddons",
        importpath = "cloud.google.com/go/gsuiteaddons",
        sum = "h1:Dayrv57XW8kZIvmQjAc89Tp7Kr3O9Am/hf6pXkTjYFY=",
        version = "v1.7.8",
    )
    go_repository(
        name = "com_google_cloud_go_iam",
        importpath = "cloud.google.com/go/iam",
        sum = "h1:+vMINPiDF2ognBJ97ABAYYwRgsaqxPbQDlMnbHMjolc=",
        version = "v1.5.3",
    )
    go_repository(
        name = "com_google_cloud_go_iap",
        importpath = "cloud.google.com/go/iap",
        sum = "h1:Nheb77nO0/pECm/thoE3wHVAbkQSI+G8KBWviqBepiA=",
        version = "v1.11.3",
    )
    go_repository(
        name = "com_google_cloud_go_ids",
        importpath = "cloud.google.com/go/ids",
        sum = "h1:V0pSk+KKW+5/AVpeQMhM9D1VI7aMZkayj5jddNETJos=",
        version = "v1.5.7",
    )
    go_repository(
        name = "com_google_cloud_go_iot",
        importpath = "cloud.google.com/go/iot",
        sum = "h1:PDUtxCzlFwFHODEFAgaGJy/Zv4tdvLbZ+lvZ1mKQXE4=",
        version = "v1.8.7",
    )
    go_repository(
        name = "com_google_cloud_go_kms",
        importpath = "cloud.google.com/go/kms",
        sum = "h1:4IYDQL5hG4L+HzJBhzejUySoUOheh3Lk5YT4PCyyW6k=",
        version = "v1.23.2",
    )
    go_repository(
        name = "com_google_cloud_go_language",
        importpath = "cloud.google.com/go/language",
        sum = "h1:/0Fbd3/T4oNmpPqIq5/hrWdHc/eoYGtVH5lDNkuHH3k=",
        version = "v1.14.6",
    )
    go_repository(
        name = "com_google_cloud_go_lifesciences",
        importpath = "cloud.google.com/go/lifesciences",
        sum = "h1:MO5aBahcYv7JeuCpHbg/11h7KL/BYt1+PpgHhleLDbI=",
        version = "v0.10.7",
    )
    go_repository(
        name = "com_google_cloud_go_logging",
        importpath = "cloud.google.com/go/logging",
        sum = "h1:O7LvmO0kGLaHY/gq8cV7T0dyp6zJhYAOtZPX4TF3QtY=",
        version = "v1.13.1",
    )
    go_repository(
        name = "com_google_cloud_go_longrunning",
        importpath = "cloud.google.com/go/longrunning",
        sum = "h1:FV0+SYF1RIj59gyoWDRi45GiYUMM3K1qO51qoboQT1E=",
        version = "v0.7.0",
    )
    go_repository(
        name = "com_google_cloud_go_managedidentities",
        importpath = "cloud.google.com/go/managedidentities",
        sum = "h1:vC/q7D+97PZfb0UNf7r/+/clHauuaf1PqWwP7neuaeg=",
        version = "v1.7.7",
    )
    go_repository(
        name = "com_google_cloud_go_maps",
        importpath = "cloud.google.com/go/maps",
        sum = "h1:tcdo9oB3Ap4N9JJJFOhxRFldKUok4Mesd3ta7Rm79r0=",
        version = "v1.26.0",
    )
    go_repository(
        name = "com_google_cloud_go_mediatranslation",
        importpath = "cloud.google.com/go/mediatranslation",
        sum = "h1:JXbjms+JxgaWkj/YuaQm1OeCzuF+IZCDV17uUcZgFOU=",
        version = "v0.9.7",
    )
    go_repository(
        name = "com_google_cloud_go_memcache",
        importpath = "cloud.google.com/go/memcache",
        sum = "h1:ZDIfIMZsKKPzwdbvTMOL1il0shX24J7B9DC+sEt4Yj4=",
        version = "v1.11.7",
    )
    go_repository(
        name = "com_google_cloud_go_metastore",
        importpath = "cloud.google.com/go/metastore",
        sum = "h1:nfyUDD9AeKIs6btY5buQ1No0OVco20WpX9wIruL8UOA=",
        version = "v1.14.8",
    )
    go_repository(
        name = "com_google_cloud_go_monitoring",
        importpath = "cloud.google.com/go/monitoring",
        sum = "h1:dde+gMNc0UhPZD1Azu6at2e79bfdztVDS5lvhOdsgaE=",
        version = "v1.24.3",
    )
    go_repository(
        name = "com_google_cloud_go_networkconnectivity",
        importpath = "cloud.google.com/go/networkconnectivity",
        sum = "h1:n0IzhdgSNzIKQygWwDV8yKRXkZpX3FsjCYFbO9iNHPU=",
        version = "v1.19.1",
    )
    go_repository(
        name = "com_google_cloud_go_networkmanagement",
        importpath = "cloud.google.com/go/networkmanagement",
        sum = "h1:041d0RqmwP/H7AWkF/AoAwFvuCkz8shUMA4EoQt0lOA=",
        version = "v1.21.0",
    )
    go_repository(
        name = "com_google_cloud_go_networksecurity",
        importpath = "cloud.google.com/go/networksecurity",
        sum = "h1:J5gdG7mHdRLrsyM7yy4nKFgbN8+geaOo/4Zpeh4DWrg=",
        version = "v0.10.7",
    )
    go_repository(
        name = "com_google_cloud_go_notebooks",
        importpath = "cloud.google.com/go/notebooks",
        sum = "h1:g5LTI1LHa/86abDTWd8nrq7/4qq8oFhVx1SmnNpZLVg=",
        version = "v1.12.7",
    )
    go_repository(
        name = "com_google_cloud_go_optimization",
        importpath = "cloud.google.com/go/optimization",
        sum = "h1:dMtxINB6G7wULbdm8nZ/x1NMa579Q+GfJc5gaN8VeDw=",
        version = "v1.7.7",
    )
    go_repository(
        name = "com_google_cloud_go_orchestration",
        importpath = "cloud.google.com/go/orchestration",
        sum = "h1:TVWDiZyvcflLFeTQH2GexHmtJ6iUSjzr0zsSiT338dA=",
        version = "v1.11.10",
    )
    go_repository(
        name = "com_google_cloud_go_orgpolicy",
        importpath = "cloud.google.com/go/orgpolicy",
        sum = "h1:0hq12wxNwcfUMojr5j3EjWECSInIuyYDhkAWXTomRhc=",
        version = "v1.15.1",
    )
    go_repository(
        name = "com_google_cloud_go_osconfig",
        importpath = "cloud.google.com/go/osconfig",
        sum = "h1:QQzK5njfsfO2rdOWYVDyLQktqSq9gKf2ohRYeKUuA10=",
        version = "v1.15.1",
    )
    go_repository(
        name = "com_google_cloud_go_oslogin",
        importpath = "cloud.google.com/go/oslogin",
        sum = "h1:YQ8P/+MLwH0tpENYU9QOgwKQxe8DYfAKxIfm6y+OBtA=",
        version = "v1.14.7",
    )
    go_repository(
        name = "com_google_cloud_go_phishingprotection",
        importpath = "cloud.google.com/go/phishingprotection",
        sum = "h1:ZJqHirY2/H6s+uTq1y1iiVASzm3ZuDiMglT5NXywPBE=",
        version = "v0.9.7",
    )
    go_repository(
        name = "com_google_cloud_go_policytroubleshooter",
        importpath = "cloud.google.com/go/policytroubleshooter",
        sum = "h1:Bbj1EiVh96u9mfO2p+JNoHrvvyC0Ms6zP+vxqQnsaG8=",
        version = "v1.11.7",
    )
    go_repository(
        name = "com_google_cloud_go_privatecatalog",
        importpath = "cloud.google.com/go/privatecatalog",
        sum = "h1:yOdy85WDvSCPxAMixkhs5X0Z96D74kosgOTp7aJEYvU=",
        version = "v0.10.8",
    )
    go_repository(
        name = "com_google_cloud_go_pubsub",
        importpath = "cloud.google.com/go/pubsub",
        sum = "h1:fzbXpPyJnSGvWXF1jabhQeXyxdbCIkXTpjXHy7xviBM=",
        version = "v1.50.1",
    )
    go_repository(
        name = "com_google_cloud_go_pubsub_v2",
        importpath = "cloud.google.com/go/pubsub/v2",
        sum = "h1:0qS6mRJ41gD1lNmM/vdm6bR7DQu6coQcVwD+VPf0Bz0=",
        version = "v2.0.0",
    )
    go_repository(
        name = "com_google_cloud_go_pubsublite",
        importpath = "cloud.google.com/go/pubsublite",
        sum = "h1:jLQozsEVr+c6tOU13vDugtnaBSUy/PD5zK6mhm+uF1Y=",
        version = "v1.8.2",
    )
    go_repository(
        name = "com_google_cloud_go_recaptchaenterprise_v2",
        importpath = "cloud.google.com/go/recaptchaenterprise/v2",
        sum = "h1:Q2CcYGxcvnvng2q3o1SaOpV+rjE/AbFVYGTJomxlG4g=",
        version = "v2.20.5",
    )
    go_repository(
        name = "com_google_cloud_go_recommendationengine",
        importpath = "cloud.google.com/go/recommendationengine",
        sum = "h1:NH89CyKQP8e98kpdKLwV0jXkQGzSEEZia0V867vkoy8=",
        version = "v0.9.7",
    )
    go_repository(
        name = "com_google_cloud_go_recommender",
        importpath = "cloud.google.com/go/recommender",
        sum = "h1:ZVZg4wr1G7yzjIPcYUNSUJAaz9+2o78rmBU4QJgC7kg=",
        version = "v1.13.6",
    )
    go_repository(
        name = "com_google_cloud_go_redis",
        importpath = "cloud.google.com/go/redis",
        sum = "h1:6LI8zSt+vmE3WQ7hE5GsJ13CbJBLV1qUw6B7CY31Wcw=",
        version = "v1.18.3",
    )
    go_repository(
        name = "com_google_cloud_go_resourcemanager",
        importpath = "cloud.google.com/go/resourcemanager",
        sum = "h1:oPZKIdjyVTuag+D4HF7HO0mnSqcqgjcuA18xblwA0V0=",
        version = "v1.10.7",
    )
    go_repository(
        name = "com_google_cloud_go_resourcesettings",
        importpath = "cloud.google.com/go/resourcesettings",
        sum = "h1:13HOFU7v4cEvIHXSAQbinF4wp2Baybbq7q9FMctg1Ek=",
        version = "v1.8.3",
    )
    go_repository(
        name = "com_google_cloud_go_retail",
        importpath = "cloud.google.com/go/retail",
        sum = "h1:S9Rl1sB6Dmdak5y9I2Pwn9hcWA5ubk33Vnevxw+CSrI=",
        version = "v1.25.1",
    )
    go_repository(
        name = "com_google_cloud_go_run",
        importpath = "cloud.google.com/go/run",
        sum = "h1:zoXZ+vavS6k8wzEPlxMuh5rGkhQb5CAzrcfSFBInlS4=",
        version = "v1.12.1",
    )
    go_repository(
        name = "com_google_cloud_go_scheduler",
        importpath = "cloud.google.com/go/scheduler",
        sum = "h1:BoXY2BvBsaRw3ggVMzC9tborZqJBu+NcJcD9PqeC5Kc=",
        version = "v1.11.8",
    )
    go_repository(
        name = "com_google_cloud_go_secretmanager",
        importpath = "cloud.google.com/go/secretmanager",
        sum = "h1:19QT7ZsLJ8FSP1k+4esQvuCD7npMJml6hYzilxVyT+k=",
        version = "v1.16.0",
    )
    go_repository(
        name = "com_google_cloud_go_security",
        importpath = "cloud.google.com/go/security",
        sum = "h1:cF3FkCRRbRC1oXuaGZFl3qU2sdu2gP3iOAHKzL5y04Y=",
        version = "v1.19.2",
    )
    go_repository(
        name = "com_google_cloud_go_securitycenter",
        importpath = "cloud.google.com/go/securitycenter",
        sum = "h1:D9zpeguY4frQU35GBw8+M6Gw79CiuTF9iVs4sFm3FDY=",
        version = "v1.38.1",
    )
    go_repository(
        name = "com_google_cloud_go_servicedirectory",
        importpath = "cloud.google.com/go/servicedirectory",
        sum = "h1:je2yZlVcVFI/TshPXjjF9ZAlWedj0s5EbO2kozJrzBo=",
        version = "v1.12.7",
    )
    go_repository(
        name = "com_google_cloud_go_shell",
        importpath = "cloud.google.com/go/shell",
        sum = "h1:K1C9sh9EuNNhGpyCoqRdeudcU9zmfYTA95bhF5cokK8=",
        version = "v1.8.7",
    )
    go_repository(
        name = "com_google_cloud_go_spanner",
        importpath = "cloud.google.com/go/spanner",
        sum = "h1:lSeVPwUotuKTpf8K6BPitzneQfGu73QcDFIca2lshG8=",
        version = "v1.86.1",
    )
    go_repository(
        name = "com_google_cloud_go_speech",
        importpath = "cloud.google.com/go/speech",
        sum = "h1:L8kq/CypGn6y/FbipyAPyn1L9JDW4CK3zkcAe4oDN7U=",
        version = "v1.28.1",
    )
    go_repository(
        name = "com_google_cloud_go_storagetransfer",
        importpath = "cloud.google.com/go/storagetransfer",
        sum = "h1:Sjukr1LtUt7vLTHNvGc2gaAqlXNFeDFRIRmWGrFaJlY=",
        version = "v1.13.1",
    )
    go_repository(
        name = "com_google_cloud_go_talent",
        importpath = "cloud.google.com/go/talent",
        sum = "h1:1kJJ+WCY5LZ1A4rCa32zKh3N2xT3I8koiS63+vV0WC4=",
        version = "v1.8.4",
    )
    go_repository(
        name = "com_google_cloud_go_texttospeech",
        importpath = "cloud.google.com/go/texttospeech",
        sum = "h1:Ra4w+6qmaeb12ozlPBqGw8Jzdge1yfzhvZgcXWdXw30=",
        version = "v1.16.0",
    )
    go_repository(
        name = "com_google_cloud_go_tpu",
        importpath = "cloud.google.com/go/tpu",
        sum = "h1:5DDheA1f7yZ/KUbVT/9lL+Yhgd3IqHDSVVrSqDVkAFY=",
        version = "v1.8.4",
    )
    go_repository(
        name = "com_google_cloud_go_trace",
        importpath = "cloud.google.com/go/trace",
        sum = "h1:kDNDX8JkaAG3R2nq1lIdkb7FCSi1rCmsEtKVsty7p+U=",
        version = "v1.11.7",
    )
    go_repository(
        name = "com_google_cloud_go_translate",
        importpath = "cloud.google.com/go/translate",
        sum = "h1:aSxMbfJ3MVmEdQzu5jGXmPPxCAb1ySsor2yBMCI5MT4=",
        version = "v1.12.7",
    )
    go_repository(
        name = "com_google_cloud_go_video",
        importpath = "cloud.google.com/go/video",
        sum = "h1:Hp+2AeM7b3AagdHcyh2820UTzSbGyqpFJVMu0nHbBcw=",
        version = "v1.27.1",
    )
    go_repository(
        name = "com_google_cloud_go_videointelligence",
        importpath = "cloud.google.com/go/videointelligence",
        sum = "h1:FisUrSZ+y3oLuGdlFQQgZoNTDm7FAfb2hwSTsSqX+9g=",
        version = "v1.12.7",
    )
    go_repository(
        name = "com_google_cloud_go_vision_v2",
        importpath = "cloud.google.com/go/vision/v2",
        sum = "h1:9UtOINPF8p9VACQ6KAyR/ZtkpuBHGmJsprutYupDcN0=",
        version = "v2.9.6",
    )
    go_repository(
        name = "com_google_cloud_go_vmmigration",
        importpath = "cloud.google.com/go/vmmigration",
        sum = "h1:7IED5P1BmZIDy0U9Co0OYGQkFK/19/7Y6xlCaitmIcs=",
        version = "v1.9.1",
    )
    go_repository(
        name = "com_google_cloud_go_vmwareengine",
        importpath = "cloud.google.com/go/vmwareengine",
        sum = "h1:TKvULKbk44QrIx674cnoVjcZueXhyCAm2sNAJu/S1ds=",
        version = "v1.3.6",
    )
    go_repository(
        name = "com_google_cloud_go_vpcaccess",
        importpath = "cloud.google.com/go/vpcaccess",
        sum = "h1:K6siDR1T4HgSTv6sy6CAwupY7UGza6TQ1O8jtvEYoX4=",
        version = "v1.8.7",
    )
    go_repository(
        name = "com_google_cloud_go_webrisk",
        importpath = "cloud.google.com/go/webrisk",
        sum = "h1:q6zEdVgD8Ka+4fQl3azDcSNRug8clNnQ9iVS2iLh+MM=",
        version = "v1.11.2",
    )
    go_repository(
        name = "com_google_cloud_go_websecurityscanner",
        importpath = "cloud.google.com/go/websecurityscanner",
        sum = "h1:udhvvDDRryM3nrITJk/eQe74D06KK2N3SF60/FH2njQ=",
        version = "v1.7.7",
    )
    go_repository(
        name = "com_google_cloud_go_workflows",
        importpath = "cloud.google.com/go/workflows",
        sum = "h1:FGF6QEl3rtOSIHPOMZofWRVy3KNx26jDdgoYzJZ6ZhY=",
        version = "v1.14.3",
    )
    go_repository(
        name = "dev_cel_expr",
        importpath = "cel.dev/expr",
        sum = "h1:56OvJKSH3hDGL0ml5uSxZmz3/3Pq4tJ+fb1unVLAFcY=",
        version = "v0.24.0",
    )
    go_repository(
        name = "in_gopkg_check_v1",
        importpath = "gopkg.in/check.v1",
        sum = "h1:Hei/4ADfdWqJk1ZMxUNpqntNwaWcugrBjAiHlqqRiVk=",
        version = "v1.0.0-20201130134442-10cb98267c6c",
    )
    go_repository(
        name = "in_gopkg_yaml_v3",
        importpath = "gopkg.in/yaml.v3",
        sum = "h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=",
        version = "v3.0.1",
    )
    go_repository(
        name = "in_yaml_go_yaml_v2",
        importpath = "go.yaml.in/yaml/v2",
        sum = "h1:6gvOSjQoTB3vt1l+CU+tSyi/HOjfOjRLJ4YwYZGwRO0=",
        version = "v2.4.3",
    )
    go_repository(
        name = "io_opencensus_go",
        importpath = "go.opencensus.io",
        sum = "h1:y73uSU6J157QMP2kn2r30vwW1A2W2WFwSCGnAVxeaD0=",
        version = "v0.24.0",
    )
    go_repository(
        name = "io_opentelemetry_go_auto_sdk",
        importpath = "go.opentelemetry.io/auto/sdk",
        sum = "h1:jXsnJ4Lmnqd11kwkBV2LgLoFMZKizbCi5fNZ/ipaZ64=",
        version = "v1.2.1",
    )
    go_repository(
        name = "io_opentelemetry_go_contrib_detectors_gcp",
        importpath = "go.opentelemetry.io/contrib/detectors/gcp",
        sum = "h1:ZoYbqX7OaA/TAikspPl3ozPI6iY6LiIY9I8cUfm+pJs=",
        version = "v1.38.0",
    )
    go_repository(
        name = "io_opentelemetry_go_contrib_instrumentation_google_golang_org_grpc_otelgrpc",
        importpath = "go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc",
        sum = "h1:RN3ifU8y4prNWeEnQp2kRRHz8UwonAEYZl8tUzHEXAk=",
        version = "v0.64.0",
    )
    go_repository(
        name = "io_opentelemetry_go_contrib_instrumentation_net_http_otelhttp",
        importpath = "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp",
        sum = "h1:ssfIgGNANqpVFCndZvcuyKbl0g+UAVcbBcqGkG28H0Y=",
        version = "v0.64.0",
    )
    go_repository(
        name = "io_opentelemetry_go_otel",
        importpath = "go.opentelemetry.io/otel",
        sum = "h1:8yPrr/S0ND9QEfTfdP9V+SiwT4E0G7Y5MO7p85nis48=",
        version = "v1.39.0",
    )
    go_repository(
        name = "io_opentelemetry_go_otel_metric",
        importpath = "go.opentelemetry.io/otel/metric",
        sum = "h1:d1UzonvEZriVfpNKEVmHXbdf909uGTOQjA0HF0Ls5Q0=",
        version = "v1.39.0",
    )
    go_repository(
        name = "io_opentelemetry_go_otel_sdk",
        importpath = "go.opentelemetry.io/otel/sdk",
        sum = "h1:nMLYcjVsvdui1B/4FRkwjzoRVsMK8uL/cj0OyhKzt18=",
        version = "v1.39.0",
    )
    go_repository(
        name = "io_opentelemetry_go_otel_sdk_metric",
        importpath = "go.opentelemetry.io/otel/sdk/metric",
        sum = "h1:cXMVVFVgsIf2YL6QkRF4Urbr/aMInf+2WKg+sEJTtB8=",
        version = "v1.39.0",
    )
    go_repository(
        name = "io_opentelemetry_go_otel_trace",
        importpath = "go.opentelemetry.io/otel/trace",
        sum = "h1:2d2vfpEDmCJ5zVYz7ijaJdOF59xLomrvj7bjt6/qCJI=",
        version = "v1.39.0",
    )
    go_repository(
        name = "org_golang_google_api",
        importpath = "google.golang.org/api",
        sum = "h1:8Y0lzvHlZps53PEaw+G29SsQIkuKrumGWs9puiexNAA=",
        version = "v0.257.0",
    )
    go_repository(
        name = "org_golang_google_appengine",
        importpath = "google.golang.org/appengine",
        sum = "h1:IhEN5q69dyKagZPYMSdIjS2HqprW324FRQZJcGqPAsM=",
        version = "v1.6.8",
    )
    go_repository(
        name = "org_golang_google_genproto",
        importpath = "google.golang.org/genproto",
        sum = "h1:GvESR9BIyHUahIb0NcTum6itIWtdoglGX+rnGxm2934=",
        version = "v0.0.0-20251202230838-ff82c1b0f217",
    )
    go_repository(
        name = "org_golang_google_genproto_googleapis_api",
        importpath = "google.golang.org/genproto/googleapis/api",
        sum = "h1:fCvbg86sFXwdrl5LgVcTEvNC+2txB5mgROGmRL5mrls=",
        version = "v0.0.0-20251202230838-ff82c1b0f217",
    )
    go_repository(
        name = "org_golang_google_genproto_googleapis_bytestream",
        importpath = "google.golang.org/genproto/googleapis/bytestream",
        sum = "h1:7FlucM2tFADtEDnIlDrR12KdRqV48B1GSTU1U6uKSiY=",
        version = "v0.0.0-20251124214823-79d6a2a48846",
    )
    go_repository(
        name = "org_golang_google_genproto_googleapis_rpc",
        importpath = "google.golang.org/genproto/googleapis/rpc",
        sum = "h1:gRkg/vSppuSQoDjxyiGfN4Upv/h/DQmIR10ZU8dh4Ww=",
        version = "v0.0.0-20251202230838-ff82c1b0f217",
    )
    go_repository(
        name = "org_golang_google_grpc",
        importpath = "google.golang.org/grpc",
        sum = "h1:wVVY6/8cGA6vvffn+wWK5ToddbgdU3d8MNENr4evgXM=",
        version = "v1.77.0",
    )
    go_repository(
        name = "org_golang_google_protobuf",
        importpath = "google.golang.org/protobuf",
        sum = "h1:AYd7cD/uASjIL6Q9LiTjz8JLcrh/88q5UObnmY3aOOE=",
        version = "v1.36.10",
    )
    go_repository(
        name = "org_golang_x_crypto",
        importpath = "golang.org/x/crypto",
        sum = "h1:cKRW/pmt1pKAfetfu+RCEvjvZkA9RimPbh7bhFjGVBU=",
        version = "v0.46.0",
    )
    go_repository(
        name = "org_golang_x_mod",
        importpath = "golang.org/x/mod",
        sum = "h1:fDEXFVZ/fmCKProc/yAXXUijritrDzahmwwefnjoPFk=",
        version = "v0.30.0",
    )
    go_repository(
        name = "org_golang_x_net",
        importpath = "golang.org/x/net",
        sum = "h1:zyQRTTrjc33Lhh0fBgT/H3oZq9WuvRR5gPC70xpDiQU=",
        version = "v0.48.0",
    )
    go_repository(
        name = "org_golang_x_oauth2",
        importpath = "golang.org/x/oauth2",
        sum = "h1:hqK/t4AKgbqWkdkcAeI8XLmbK+4m4G5YeQRrmiotGlw=",
        version = "v0.34.0",
    )
    go_repository(
        name = "org_golang_x_sync",
        importpath = "golang.org/x/sync",
        sum = "h1:vV+1eWNmZ5geRlYjzm2adRgW2/mcpevXNg50YZtPCE4=",
        version = "v0.19.0",
    )
    go_repository(
        name = "org_golang_x_sys",
        importpath = "golang.org/x/sys",
        sum = "h1:CvCKL8MeisomCi6qNZ+wbb0DN9E5AATixKsvNtMoMFk=",
        version = "v0.39.0",
    )
    go_repository(
        name = "org_golang_x_term",
        importpath = "golang.org/x/term",
        sum = "h1:PQ5pkm/rLO6HnxFR7N2lJHOZX6Kez5Y1gDSJla6jo7Q=",
        version = "v0.38.0",
    )
    go_repository(
        name = "org_golang_x_text",
        importpath = "golang.org/x/text",
        sum = "h1:ZD01bjUt1FQ9WJ0ClOL5vxgxOI/sVCNgX1YtKwcY0mU=",
        version = "v0.32.0",
    )
    go_repository(
        name = "org_golang_x_time",
        importpath = "golang.org/x/time",
        sum = "h1:MRx4UaLrDotUKUdCIqzPC48t1Y9hANFKIRpNx+Te8PI=",
        version = "v0.14.0",
    )
    go_repository(
        name = "org_golang_x_tools",
        importpath = "golang.org/x/tools",
        sum = "h1:ik4ho21kwuQln40uelmciQPp9SipgNDdrafrYA4TmQQ=",
        version = "v0.39.0",
    )
    go_repository(
        name = "org_gonum_v1_gonum",
        importpath = "gonum.org/v1/gonum",
        sum = "h1:5+ul4Swaf3ESvrOnidPp4GZbzf0mxVQpDCYUQE7OJfk=",
        version = "v0.16.0",
    )
    go_repository(
        name = "org_uber_go_goleak",
        importpath = "go.uber.org/goleak",
        sum = "h1:2K3zAYmnTNqV73imy9J1T3WC+gmCePx2hEGkimedGto=",
        version = "v1.3.0",
    )
