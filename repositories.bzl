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
        sum = "h1:s6gZFSlWYmbqAuRjVTiNNhvNRfY2Wxp9nhfyel4rklc=",
        version = "v0.0.0-20211218093645-b94a6e3cc137",
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
        sum = "h1:aQ3y1lwWyqYPiWZThqv1aFbZMiM9vblcSArJRf2Irls=",
        version = "v0.0.0-20250501225837-2ac532fd4443",
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
        sum = "h1:zEqyPVyku6IvWCFwux4x9RxkLOMUL+1vC9xUFv5l2/M=",
        version = "v0.13.4",
    )
    go_repository(
        name = "com_github_envoyproxy_go_control_plane_envoy",
        importpath = "github.com/envoyproxy/go-control-plane/envoy",
        sum = "h1:jb83lalDRZSpPWW2Z7Mck/8kXZ5CQAFYVjQcdVIr83A=",
        version = "v1.32.4",
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
        sum = "h1:QpQsORx5N2EwomFMgeeY2Vzjf4h3nS2XtD8ETonNJVY=",
        version = "v0.0.0-20250520203025-c3c3a4ec1653",
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
        sum = "h1:JYhSgy4mXXzAdF3nUx3ygx347LRXJRrpgyU3adRmkAI=",
        version = "v4.1.1",
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
        sum = "h1:ocUmnDebX54dnW+MQWGQRbdaAcJELsa6PqZhJ48KwVU=",
        version = "v0.9.5",
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
        sum = "h1:GW/XbdyBFQ8Qe+YAmFU9uHLo7OnF5tL52HFAgMmyrf4=",
        version = "v0.3.6",
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
        sum = "h1:UQUsRi8WTzhZntp5313l+CHIAT95ojUI2lpP/ExlZa4=",
        version = "v1.29.0",
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
        sum = "h1:ust4zpdl9r4trLY/gSjlm07PuiBq2ynaXXlptpfy8Uc=",
        version = "v1.23.0",
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
        sum = "h1:QDwzd+G1twt//Kwj/Ww6E9FQq1iVMmODnILtW1t2VzE=",
        version = "v0.65.0",
    )
    go_repository(
        name = "com_github_prometheus_procfs",
        importpath = "github.com/prometheus/procfs",
        sum = "h1:FuLQ+05u4ZI+SS/w9+BWEM2TXiHKsUQ9TADiRH7DuK0=",
        version = "v0.17.0",
    )
    go_repository(
        name = "com_github_rogpeppe_go_internal",
        importpath = "github.com/rogpeppe/go-internal",
        sum = "h1:KvO1DLK/DRN07sQ1LQKScxyZJuNnedQ5/wKSR38lUII=",
        version = "v1.13.1",
    )
    go_repository(
        name = "com_github_salrashid123_golang_jwt_tpm",
        importpath = "github.com/salrashid123/golang-jwt-tpm",
        sum = "h1:0n3QRq9lUtJ/ZKo7zUaBVI0J9/byBVXXw0OvQlMbhYk=",
        version = "v1.8.95",
    )
    go_repository(
        name = "com_github_salrashid123_oauth2_v3",
        importpath = "github.com/salrashid123/oauth2/v3",
        sum = "h1:4nOIOO/7HrYoLqBDxLjt/TDc3xEKRqWTo8RujBKruEw=",
        version = "v3.0.7",
    )
    go_repository(
        name = "com_github_spiffe_go_spiffe_v2",
        importpath = "github.com/spiffe/go-spiffe/v2",
        sum = "h1:N2I01KCUkv1FAjZXJMwh95KK1ZIQLYbPfhaxw8WS0hE=",
        version = "v2.5.0",
    )
    go_repository(
        name = "com_github_stretchr_testify",
        importpath = "github.com/stretchr/testify",
        sum = "h1:Xv5erBjTwe/5IxqUQTdXv5kgmIvbHo3QQyRwhJsOfJA=",
        version = "v1.10.0",
    )
    go_repository(
        name = "com_github_xhit_go_str2duration_v2",
        importpath = "github.com/xhit/go-str2duration/v2",
        sum = "h1:lxklc02Drh6ynqX+DdPyp5pCKLUQpRT8bp8Ydu2Bstc=",
        version = "v2.1.0",
    )
    go_repository(
        name = "com_github_zeebo_errs",
        importpath = "github.com/zeebo/errs",
        sum = "h1:XNdoD/RRMKP7HD0UhJnIzUy74ISdGGxURlYG8HSWSfM=",
        version = "v1.4.0",
    )
    go_repository(
        name = "com_google_cloud_go",
        importpath = "cloud.google.com/go",
        sum = "h1:wc6bgG9DHyKqF5/vQvX1CiZrtHnxJjBlKUyF9nP6meA=",
        version = "v0.120.0",
    )
    go_repository(
        name = "com_google_cloud_go_accessapproval",
        importpath = "cloud.google.com/go/accessapproval",
        sum = "h1:Sc9ZjxFBEM/PoAxNlUwVGDcv8DYyjLYWDxHlzPG0q5I=",
        version = "v1.8.7",
    )
    go_repository(
        name = "com_google_cloud_go_accesscontextmanager",
        importpath = "cloud.google.com/go/accesscontextmanager",
        sum = "h1:2LnncRqfYB8NEdh9+FeYxAt9POTW/0zVboktnRlO11w=",
        version = "v1.9.6",
    )
    go_repository(
        name = "com_google_cloud_go_aiplatform",
        importpath = "cloud.google.com/go/aiplatform",
        sum = "h1:SB4gurI6YSuZJCfAzjuIxxgbtJtczJFOTmCM7fLYRGg=",
        version = "v1.99.0",
    )
    go_repository(
        name = "com_google_cloud_go_analytics",
        importpath = "cloud.google.com/go/analytics",
        sum = "h1:oYiABctb2wxUs1khR6vpC/T4P1EN27yvKI6Fxqzuv8E=",
        version = "v0.29.0",
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
        sum = "h1:TgdjAoGoRY81DEc2LYsYvi/OqCFImMzAk/TVKiSRsQw=",
        version = "v0.9.6",
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
        sum = "h1:A20kj2S2HO9vlyBVyVFHPxArjxkXvLP5LjcdE7NhaPc=",
        version = "v1.17.1",
    )
    go_repository(
        name = "com_google_cloud_go_asset",
        importpath = "cloud.google.com/go/asset",
        sum = "h1:i55wWC/EwVdHMyJgRfbLp/L6ez4nQuOpZwSxkuqN9ek=",
        version = "v1.21.1",
    )
    go_repository(
        name = "com_google_cloud_go_assuredworkloads",
        importpath = "cloud.google.com/go/assuredworkloads",
        sum = "h1:ip/shfJYx6lrHBWYADjrrrubcm7uZzy50TTF5tPG7ek=",
        version = "v1.12.6",
    )
    go_repository(
        name = "com_google_cloud_go_auth",
        importpath = "cloud.google.com/go/auth",
        sum = "h1:mFWNQ2FEVWAliEQWpAdH80omXFokmrnbDhUS9cBywsI=",
        version = "v0.16.5",
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
        sum = "h1:ZLj48Ur2Qcso4M3bgOtjsOmeV5Ee92N14wuOc8OW+L0=",
        version = "v1.14.7",
    )
    go_repository(
        name = "com_google_cloud_go_baremetalsolution",
        importpath = "cloud.google.com/go/baremetalsolution",
        sum = "h1:9bdGlpY1LgLONQjFsDwrkjLzdPTlROpfU+GhA97YpOk=",
        version = "v1.3.6",
    )
    go_repository(
        name = "com_google_cloud_go_batch",
        importpath = "cloud.google.com/go/batch",
        sum = "h1:gWQdvdPplptpvrkqF6ibtxZkOsYKLTFbxYawHa/TvCg=",
        version = "v1.12.2",
    )
    go_repository(
        name = "com_google_cloud_go_beyondcorp",
        importpath = "cloud.google.com/go/beyondcorp",
        sum = "h1:4FcR+4QmcNGkhVij6TrYS4AQVNLBo7PBXKxNrKzpclQ=",
        version = "v1.1.6",
    )
    go_repository(
        name = "com_google_cloud_go_bigquery",
        importpath = "cloud.google.com/go/bigquery",
        sum = "h1:rZvHnjSUs5sHK3F9awiuFk2PeOaB8suqNuim21GbaTc=",
        version = "v1.69.0",
    )
    go_repository(
        name = "com_google_cloud_go_bigtable",
        importpath = "cloud.google.com/go/bigtable",
        sum = "h1:L/PnUXRtAzFfa7qMULJHt4cXa/O2dqPJEkzYNGA4hfo=",
        version = "v1.38.0",
    )
    go_repository(
        name = "com_google_cloud_go_billing",
        importpath = "cloud.google.com/go/billing",
        sum = "h1:pqM5/c9UGydB9H90IPCxSvfCNLUPazAOSMsZkz5q5P4=",
        version = "v1.20.4",
    )
    go_repository(
        name = "com_google_cloud_go_binaryauthorization",
        importpath = "cloud.google.com/go/binaryauthorization",
        sum = "h1:T0zYEroXT+y0O/x/yZd5SwQdFv4UbUINjvJyJKzDm0Q=",
        version = "v1.9.5",
    )
    go_repository(
        name = "com_google_cloud_go_certificatemanager",
        importpath = "cloud.google.com/go/certificatemanager",
        sum = "h1:+ZPglfDurCcsv4azizDFpBucD1IkRjWjbnU7zceyjfY=",
        version = "v1.9.5",
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
        sum = "h1:FnbWf1FjtyrPLVqTb5wYX8eMgrbC5w0BPhpud9fAIu8=",
        version = "v1.22.3",
    )
    go_repository(
        name = "com_google_cloud_go_clouddms",
        importpath = "cloud.google.com/go/clouddms",
        sum = "h1:IWJbQBEECTaNanDRN1XdR7FU53MJ1nylTl3s9T3MuyI=",
        version = "v1.8.7",
    )
    go_repository(
        name = "com_google_cloud_go_cloudtasks",
        importpath = "cloud.google.com/go/cloudtasks",
        sum = "h1:Fwan19UiNoFD+3KY0MnNHE5DyixOxNzS1mZ4ChOdpy0=",
        version = "v1.13.6",
    )
    go_repository(
        name = "com_google_cloud_go_compute",
        importpath = "cloud.google.com/go/compute",
        sum = "h1:6gRrxftrqe5llEyTvwPGGEqTnetXOrlLhPPyU4oTd34=",
        version = "v1.43.0",
    )
    go_repository(
        name = "com_google_cloud_go_compute_metadata",
        importpath = "cloud.google.com/go/compute/metadata",
        sum = "h1:HxMRIbao8w17ZX6wBnjhcDkW6lTFpgcaobyVfZWqRLA=",
        version = "v0.8.0",
    )
    go_repository(
        name = "com_google_cloud_go_contactcenterinsights",
        importpath = "cloud.google.com/go/contactcenterinsights",
        sum = "h1:lenyU3uzHwKDveCwmpfNxHYvLS3uEBWdn+O7+rSxy+Q=",
        version = "v1.17.3",
    )
    go_repository(
        name = "com_google_cloud_go_container",
        importpath = "cloud.google.com/go/container",
        sum = "h1:JEHeW535svvNwJrjrlQ/cdjd15LCWrPKnHsulrufd3A=",
        version = "v1.44.0",
    )
    go_repository(
        name = "com_google_cloud_go_containeranalysis",
        importpath = "cloud.google.com/go/containeranalysis",
        sum = "h1:1SoHlNqL3XrhqcoozB+3eoHif2sRUFtp/JeASQTtGKo=",
        version = "v0.14.1",
    )
    go_repository(
        name = "com_google_cloud_go_datacatalog",
        importpath = "cloud.google.com/go/datacatalog",
        sum = "h1:eFgygb3DTufTWWUB8ARk+dSuXz+aefNJXTlkWlQcWwE=",
        version = "v1.26.0",
    )
    go_repository(
        name = "com_google_cloud_go_dataflow",
        importpath = "cloud.google.com/go/dataflow",
        sum = "h1:AdhB4cAkMOC9NtrHJxpKOVvO/VqBLaIyk0tEEhbGjYM=",
        version = "v0.11.0",
    )
    go_repository(
        name = "com_google_cloud_go_dataform",
        importpath = "cloud.google.com/go/dataform",
        sum = "h1:0eCPTPUC/RZ863aVfXTJLkg0tEpdpn62VD6ywSmmzxM=",
        version = "v0.12.0",
    )
    go_repository(
        name = "com_google_cloud_go_datafusion",
        importpath = "cloud.google.com/go/datafusion",
        sum = "h1:GZ6J+CR8CEeWAj8luRCtr8GvImSQRkArIIqGiZOnzBA=",
        version = "v1.8.6",
    )
    go_repository(
        name = "com_google_cloud_go_datalabeling",
        importpath = "cloud.google.com/go/datalabeling",
        sum = "h1:VOZ5U+78ttnhNCEID7qdeogqZQzK5N+LPHIQ9Q3YDsc=",
        version = "v0.9.6",
    )
    go_repository(
        name = "com_google_cloud_go_dataplex",
        importpath = "cloud.google.com/go/dataplex",
        sum = "h1:nu8/KrLR5v62L1lApGNgm61Oq+xaa2bS9rgc1csjqE0=",
        version = "v1.26.0",
    )
    go_repository(
        name = "com_google_cloud_go_dataproc_v2",
        importpath = "cloud.google.com/go/dataproc/v2",
        sum = "h1:oiEM2efaJfiOClBOYcmW1K+tDP5pHdnYsPmfD55tiRw=",
        version = "v2.14.0",
    )
    go_repository(
        name = "com_google_cloud_go_dataqna",
        importpath = "cloud.google.com/go/dataqna",
        sum = "h1:qTRAG/E3T63Xj1orefRlwupfwH9c9ERUAnWSRGp75so=",
        version = "v0.9.7",
    )
    go_repository(
        name = "com_google_cloud_go_datastore",
        importpath = "cloud.google.com/go/datastore",
        sum = "h1:NNpXoyEqIJmZFc0ACcwBEaXnmscUpcG4NkKnbCePmiM=",
        version = "v1.20.0",
    )
    go_repository(
        name = "com_google_cloud_go_datastream",
        importpath = "cloud.google.com/go/datastream",
        sum = "h1:ZXT4aQ90rXBy6B4UjiEYDdfZULpAdP7TmAxa2ZBwf28=",
        version = "v1.15.0",
    )
    go_repository(
        name = "com_google_cloud_go_deploy",
        importpath = "cloud.google.com/go/deploy",
        sum = "h1:C0VqBhFyQFp6+xgPHZAD7LeRA4XGy5YLzGmPQ2NhlLk=",
        version = "v1.27.2",
    )
    go_repository(
        name = "com_google_cloud_go_dialogflow",
        importpath = "cloud.google.com/go/dialogflow",
        sum = "h1:nW3vH/ysZWBdjQJ4rIh3PC5Do/Brz8KEp3OeDy9VW3U=",
        version = "v1.69.0",
    )
    go_repository(
        name = "com_google_cloud_go_dlp",
        importpath = "cloud.google.com/go/dlp",
        sum = "h1:ThCQO8Qy5TAfFEJQjhq80u5c93UMdM2uqI3pUZVy7Do=",
        version = "v1.24.0",
    )
    go_repository(
        name = "com_google_cloud_go_documentai",
        importpath = "cloud.google.com/go/documentai",
        sum = "h1:7fla8GcarupO15eatRTUveXCob6DOSW1Wa+1i63CM3Q=",
        version = "v1.37.0",
    )
    go_repository(
        name = "com_google_cloud_go_domains",
        importpath = "cloud.google.com/go/domains",
        sum = "h1:TI+Aavwc31KD8huOquJz0ISchCq1zSEWc9M+JcPJyxc=",
        version = "v0.10.6",
    )
    go_repository(
        name = "com_google_cloud_go_edgecontainer",
        importpath = "cloud.google.com/go/edgecontainer",
        sum = "h1:9tfGCicvrki927T+hGMB0yYmwIbRuZY6JR1/awrKiZ0=",
        version = "v1.4.3",
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
        sum = "h1:ysHZ4gr4plW1CL1Ur/AucUUfh20hDjSFbfjxSK0q/sk=",
        version = "v1.7.6",
    )
    go_repository(
        name = "com_google_cloud_go_eventarc",
        importpath = "cloud.google.com/go/eventarc",
        sum = "h1:bZW7ZMM+XXNErg6rOZcgxUzAgz4vpReRDP3ZiGf7/sI=",
        version = "v1.15.5",
    )
    go_repository(
        name = "com_google_cloud_go_filestore",
        importpath = "cloud.google.com/go/filestore",
        sum = "h1:LjoAyp9TvVNBns3sUUzPaNsQiGpR2BReGmTS3bUCuBE=",
        version = "v1.10.2",
    )
    go_repository(
        name = "com_google_cloud_go_firestore",
        importpath = "cloud.google.com/go/firestore",
        sum = "h1:cuydCaLS7Vl2SatAeivXyhbhDEIR8BDmtn4egDhIn2s=",
        version = "v1.18.0",
    )
    go_repository(
        name = "com_google_cloud_go_functions",
        importpath = "cloud.google.com/go/functions",
        sum = "h1:vJgWlvxtJG6p/JrbXAkz83DbgwOyFhZZI1Y32vUddjY=",
        version = "v1.19.6",
    )
    go_repository(
        name = "com_google_cloud_go_gkebackup",
        importpath = "cloud.google.com/go/gkebackup",
        sum = "h1:eBqOt61yEChvj7I/GDPBbdCCRdUPudD1qrQYfYWV3Ok=",
        version = "v1.8.0",
    )
    go_repository(
        name = "com_google_cloud_go_gkeconnect",
        importpath = "cloud.google.com/go/gkeconnect",
        sum = "h1:67/rnPmF/I1Wmf7jWyKH+z4OWjU8ZUI0Vmzxvmzf3KY=",
        version = "v0.12.4",
    )
    go_repository(
        name = "com_google_cloud_go_gkehub",
        importpath = "cloud.google.com/go/gkehub",
        sum = "h1:9iogrmNNa+drDPf/zkLH/6KGgUf7FuuyokmithoGwMQ=",
        version = "v0.15.6",
    )
    go_repository(
        name = "com_google_cloud_go_gkemulticloud",
        importpath = "cloud.google.com/go/gkemulticloud",
        sum = "h1:334aZmOzIt3LVBpguCof8IHaLaftcZlx+L0TGBukYkY=",
        version = "v1.5.3",
    )
    go_repository(
        name = "com_google_cloud_go_gsuiteaddons",
        importpath = "cloud.google.com/go/gsuiteaddons",
        sum = "h1:sk0SxpCGIA7tIO//XdiiG29f2vrF6Pq/dsxxyBGiRBY=",
        version = "v1.7.7",
    )
    go_repository(
        name = "com_google_cloud_go_iam",
        importpath = "cloud.google.com/go/iam",
        sum = "h1:qgFRAGEmd8z6dJ/qyEchAuL9jpswyODjA2lS+w234g8=",
        version = "v1.5.2",
    )
    go_repository(
        name = "com_google_cloud_go_iap",
        importpath = "cloud.google.com/go/iap",
        sum = "h1:VIioCrYsyWiRGx7Y8RDNylpI6d4t1Qx5ZgSLUVmWWPo=",
        version = "v1.11.2",
    )
    go_repository(
        name = "com_google_cloud_go_ids",
        importpath = "cloud.google.com/go/ids",
        sum = "h1:uKGuaWozDcjg3wyf54Gd7tCH2YK8BFeH9qo1xBNiPKE=",
        version = "v1.5.6",
    )
    go_repository(
        name = "com_google_cloud_go_iot",
        importpath = "cloud.google.com/go/iot",
        sum = "h1:A3AhugnIViAZkC3/lHAQDaXBIk2ZOPBZS0XQCyZsjjc=",
        version = "v1.8.6",
    )
    go_repository(
        name = "com_google_cloud_go_kms",
        importpath = "cloud.google.com/go/kms",
        sum = "h1:dBRIj7+GDeeEvatJeTB19oYZNV0aj6wEqSIT/7gLqtk=",
        version = "v1.22.0",
    )
    go_repository(
        name = "com_google_cloud_go_language",
        importpath = "cloud.google.com/go/language",
        sum = "h1:BVJ/POtlnJ55LElvnQY19UOxpMVtHoHHkFJW2uHJsVU=",
        version = "v1.14.5",
    )
    go_repository(
        name = "com_google_cloud_go_lifesciences",
        importpath = "cloud.google.com/go/lifesciences",
        sum = "h1:Vu7XF4s5KJ8+mSLIL4eaQM6JTyWXvSB54oqC+CUZH20=",
        version = "v0.10.6",
    )
    go_repository(
        name = "com_google_cloud_go_logging",
        importpath = "cloud.google.com/go/logging",
        sum = "h1:7j0HgAp0B94o1YRDqiqm26w4q1rDMH7XNRU34lJXHYc=",
        version = "v1.13.0",
    )
    go_repository(
        name = "com_google_cloud_go_longrunning",
        importpath = "cloud.google.com/go/longrunning",
        sum = "h1:IGtfDWHhQCgCjwQjV9iiLnUta9LBCo8R9QmAFsS/PrE=",
        version = "v0.6.7",
    )
    go_repository(
        name = "com_google_cloud_go_managedidentities",
        importpath = "cloud.google.com/go/managedidentities",
        sum = "h1:zrZVWXZJlmHnfpyCrTQIbDBGUBHrcOOvrsjMjoXRxrk=",
        version = "v1.7.6",
    )
    go_repository(
        name = "com_google_cloud_go_maps",
        importpath = "cloud.google.com/go/maps",
        sum = "h1:Rgs6jvqYztt28cKTh9hzk/a2qq/83FrqR92nPM3bb10=",
        version = "v1.22.0",
    )
    go_repository(
        name = "com_google_cloud_go_mediatranslation",
        importpath = "cloud.google.com/go/mediatranslation",
        sum = "h1:SDGatA73TgZ8iCvILVXpk/1qhTK5DJyufUDEWgbmbV8=",
        version = "v0.9.6",
    )
    go_repository(
        name = "com_google_cloud_go_memcache",
        importpath = "cloud.google.com/go/memcache",
        sum = "h1:33IVqQEmFiITsBXwGHeTkUhWz0kLNKr90nV3e22uLPs=",
        version = "v1.11.6",
    )
    go_repository(
        name = "com_google_cloud_go_metastore",
        importpath = "cloud.google.com/go/metastore",
        sum = "h1:dLm59AHHZCorveCylj7c2iWhkQsmMIeWTsV+tG/BXtY=",
        version = "v1.14.7",
    )
    go_repository(
        name = "com_google_cloud_go_monitoring",
        importpath = "cloud.google.com/go/monitoring",
        sum = "h1:5OTsoJ1dXYIiMiuL+sYscLc9BumrL3CarVLL7dd7lHM=",
        version = "v1.24.2",
    )
    go_repository(
        name = "com_google_cloud_go_networkconnectivity",
        importpath = "cloud.google.com/go/networkconnectivity",
        sum = "h1:dQxh+/LBr8heinPCwjlYHZAr4IU7qCusl5yMK9+9apU=",
        version = "v1.18.0",
    )
    go_repository(
        name = "com_google_cloud_go_networkmanagement",
        importpath = "cloud.google.com/go/networkmanagement",
        sum = "h1:xU5mNtugdHmeZfsJKDi+agkKC3joY2Mp750AAhqk9Qs=",
        version = "v1.20.0",
    )
    go_repository(
        name = "com_google_cloud_go_networksecurity",
        importpath = "cloud.google.com/go/networksecurity",
        sum = "h1:6b6fcCG9BFNcmtNO+VuPE04vkZb5TKNX9+7ZhYMgstE=",
        version = "v0.10.6",
    )
    go_repository(
        name = "com_google_cloud_go_notebooks",
        importpath = "cloud.google.com/go/notebooks",
        sum = "h1:nCfZwVihArMPP2atRoxRrXOXJ/aC9rAgpBQGCc2zpYw=",
        version = "v1.12.6",
    )
    go_repository(
        name = "com_google_cloud_go_optimization",
        importpath = "cloud.google.com/go/optimization",
        sum = "h1:jDvIuSxDsXI2P7l2sYXm6CoX1YBIIT6Khm5m0hq0/KQ=",
        version = "v1.7.6",
    )
    go_repository(
        name = "com_google_cloud_go_orchestration",
        importpath = "cloud.google.com/go/orchestration",
        sum = "h1:PnlZ/O4R/eiounpxUkhI9ZXRMWbG7vFqxc6L6sR+31k=",
        version = "v1.11.9",
    )
    go_repository(
        name = "com_google_cloud_go_orgpolicy",
        importpath = "cloud.google.com/go/orgpolicy",
        sum = "h1:uQziDu3UKYk9ZwUgneZAW5aWxZFKgOXXsuVKFKh0z7Y=",
        version = "v1.15.0",
    )
    go_repository(
        name = "com_google_cloud_go_osconfig",
        importpath = "cloud.google.com/go/osconfig",
        sum = "h1:7ol0qfm+vzfgNtGcLVJevs7UW/7JR+MlmPI/LqoZrUM=",
        version = "v1.15.0",
    )
    go_repository(
        name = "com_google_cloud_go_oslogin",
        importpath = "cloud.google.com/go/oslogin",
        sum = "h1:BDKVcxo1OO4ZT+PbuFchZjnbrlUGfChilt6+pITY1VI=",
        version = "v1.14.6",
    )
    go_repository(
        name = "com_google_cloud_go_phishingprotection",
        importpath = "cloud.google.com/go/phishingprotection",
        sum = "h1:yl572bBQbPjflX250SOflN6gwO2uYoddN2uRp36fDTo=",
        version = "v0.9.6",
    )
    go_repository(
        name = "com_google_cloud_go_policytroubleshooter",
        importpath = "cloud.google.com/go/policytroubleshooter",
        sum = "h1:Z8+tO2z21MY1arBBuJjwrOjbw8fbZb13AZTHXdzkl2U=",
        version = "v1.11.6",
    )
    go_repository(
        name = "com_google_cloud_go_privatecatalog",
        importpath = "cloud.google.com/go/privatecatalog",
        sum = "h1:R951ikhxIanXEijBCu0xnoUAOteS5m/Xplek0YvsNTE=",
        version = "v0.10.7",
    )
    go_repository(
        name = "com_google_cloud_go_pubsub",
        importpath = "cloud.google.com/go/pubsub",
        sum = "h1:hnYpOIxVlgVD1Z8LN7est4DQZK3K6tvZNurZjIVjUe0=",
        version = "v1.50.0",
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
        sum = "h1:P4QMryKcWdi4LIe1Sx0b2ZOAQv5gVfdzPt2peXcN32Y=",
        version = "v2.20.4",
    )
    go_repository(
        name = "com_google_cloud_go_recommendationengine",
        importpath = "cloud.google.com/go/recommendationengine",
        sum = "h1:slN7h23vswGccW8x3f+xUXCu9Yo18/GNkazH93LJbFk=",
        version = "v0.9.6",
    )
    go_repository(
        name = "com_google_cloud_go_recommender",
        importpath = "cloud.google.com/go/recommender",
        sum = "h1:cIsyRKGNw4LpCfY5c8CCQadhlp54jP4fHtP+d5Sy2xE=",
        version = "v1.13.5",
    )
    go_repository(
        name = "com_google_cloud_go_redis",
        importpath = "cloud.google.com/go/redis",
        sum = "h1:JlHLceAOILEmbn+NIS7l+vmUKkFuobLToCWTxL7NGcQ=",
        version = "v1.18.2",
    )
    go_repository(
        name = "com_google_cloud_go_resourcemanager",
        importpath = "cloud.google.com/go/resourcemanager",
        sum = "h1:LIa8kKE8HF71zm976oHMqpWFiaDHVw/H1YMO71lrGmo=",
        version = "v1.10.6",
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
        sum = "h1:2jXyUed1nbv4aL2drKF/HbQnN1TgEorWHp1EAxNNetg=",
        version = "v1.24.0",
    )
    go_repository(
        name = "com_google_cloud_go_run",
        importpath = "cloud.google.com/go/run",
        sum = "h1:l4tpqhzJ75uOugXl2BQ15uEM5gLamVH5M70tBv70ZCU=",
        version = "v1.12.0",
    )
    go_repository(
        name = "com_google_cloud_go_scheduler",
        importpath = "cloud.google.com/go/scheduler",
        sum = "h1:zkMEJ0UbEJ3O7NwEUlKLIp6eXYv1L7wHjbxyxznajKM=",
        version = "v1.11.7",
    )
    go_repository(
        name = "com_google_cloud_go_secretmanager",
        importpath = "cloud.google.com/go/secretmanager",
        sum = "h1:RtkCMgTpaBMbzozcRUGfZe46jb9a3qh5EdEtVRUATF8=",
        version = "v1.15.0",
    )
    go_repository(
        name = "com_google_cloud_go_security",
        importpath = "cloud.google.com/go/security",
        sum = "h1:GI6kufPbHFINq998M7x60rfV5MVo6yhD+uVrjNzueKw=",
        version = "v1.19.0",
    )
    go_repository(
        name = "com_google_cloud_go_securitycenter",
        importpath = "cloud.google.com/go/securitycenter",
        sum = "h1:UR8cUgXFYpWxKkKnUNy65hlrAzgwBZBVxZilJ50ESXU=",
        version = "v1.37.0",
    )
    go_repository(
        name = "com_google_cloud_go_servicedirectory",
        importpath = "cloud.google.com/go/servicedirectory",
        sum = "h1:pl/KUNvFzlXpxgnPgzQjyTQQcv5WsQ97zCHaPrLQlYA=",
        version = "v1.12.6",
    )
    go_repository(
        name = "com_google_cloud_go_shell",
        importpath = "cloud.google.com/go/shell",
        sum = "h1:jLWyztGlNWBx55QXBM4HbWvfv7aiRjPzRKTUkZA8dXk=",
        version = "v1.8.6",
    )
    go_repository(
        name = "com_google_cloud_go_spanner",
        importpath = "cloud.google.com/go/spanner",
        sum = "h1:ShH4Y3YeDtmHa55dFiSS3YtQ0dmCuP0okfAoHp/d68w=",
        version = "v1.84.1",
    )
    go_repository(
        name = "com_google_cloud_go_speech",
        importpath = "cloud.google.com/go/speech",
        sum = "h1:9AuiAxDTmh/aeREtw+/0e7aI27T5QN4fK5lhssc9MxA=",
        version = "v1.28.0",
    )
    go_repository(
        name = "com_google_cloud_go_storagetransfer",
        importpath = "cloud.google.com/go/storagetransfer",
        sum = "h1:uqKX3OgcYzR1W1YI943ZZ45id0RqA2eXXoCBSPstlbw=",
        version = "v1.13.0",
    )
    go_repository(
        name = "com_google_cloud_go_talent",
        importpath = "cloud.google.com/go/talent",
        sum = "h1:wDP+++O/P1cTJBMkYlSY46k0a6atSoyO+UkBGuU9+Ao=",
        version = "v1.8.3",
    )
    go_repository(
        name = "com_google_cloud_go_texttospeech",
        importpath = "cloud.google.com/go/texttospeech",
        sum = "h1:oWWFQp0yFl4EJOr3opDkKH9304wUsZjgPjrTDS6S1a8=",
        version = "v1.13.0",
    )
    go_repository(
        name = "com_google_cloud_go_tpu",
        importpath = "cloud.google.com/go/tpu",
        sum = "h1:S4Ptq+yFIPNLEzQ/OQwiIYDNzk5I2vYmhf0SmFQOmWo=",
        version = "v1.8.3",
    )
    go_repository(
        name = "com_google_cloud_go_trace",
        importpath = "cloud.google.com/go/trace",
        sum = "h1:2O2zjPzqPYAHrn3OKl029qlqG6W8ZdYaOWRyr8NgMT4=",
        version = "v1.11.6",
    )
    go_repository(
        name = "com_google_cloud_go_translate",
        importpath = "cloud.google.com/go/translate",
        sum = "h1:QHcszWZvBLEZHM2WJ6IDg2BUTWzEPMiHhbJAd15yKGU=",
        version = "v1.12.6",
    )
    go_repository(
        name = "com_google_cloud_go_video",
        importpath = "cloud.google.com/go/video",
        sum = "h1:M/krJJDgUgZszzFgv7qHRltSVMafXgcuYyCETSH1oyA=",
        version = "v1.25.0",
    )
    go_repository(
        name = "com_google_cloud_go_videointelligence",
        importpath = "cloud.google.com/go/videointelligence",
        sum = "h1:heq7jEO39sH5TycBh8TGFJ827XCxK0tIWatmBY/n0jI=",
        version = "v1.12.6",
    )
    go_repository(
        name = "com_google_cloud_go_vision_v2",
        importpath = "cloud.google.com/go/vision/v2",
        sum = "h1:UJZ0H6UlOaYKgCn6lWG2iMAOJIsJZLnseEfzBR8yIqQ=",
        version = "v2.9.5",
    )
    go_repository(
        name = "com_google_cloud_go_vmmigration",
        importpath = "cloud.google.com/go/vmmigration",
        sum = "h1:68hOQDhs1DOITrCrhritrwr8xy6s8QMdwDyMzMiFleU=",
        version = "v1.8.6",
    )
    go_repository(
        name = "com_google_cloud_go_vmwareengine",
        importpath = "cloud.google.com/go/vmwareengine",
        sum = "h1:OsGd1SB91y9fDuzdzFngMv4UcT4cqmRxjsCsS4Xmcu8=",
        version = "v1.3.5",
    )
    go_repository(
        name = "com_google_cloud_go_vpcaccess",
        importpath = "cloud.google.com/go/vpcaccess",
        sum = "h1:RYtUB9rQEijX9Tc6lQcGst58ZOzPgaYTkz6+2pyPQTM=",
        version = "v1.8.6",
    )
    go_repository(
        name = "com_google_cloud_go_webrisk",
        importpath = "cloud.google.com/go/webrisk",
        sum = "h1:yZKNB7zRxOMriLrhP5WDE+BjxXVl0wJHHZSdaYzbdVU=",
        version = "v1.11.1",
    )
    go_repository(
        name = "com_google_cloud_go_websecurityscanner",
        importpath = "cloud.google.com/go/websecurityscanner",
        sum = "h1:cIPKJKZA3l7D8DfL4nxce8HGOWXBw3WAUBF0ymOW9GQ=",
        version = "v1.7.6",
    )
    go_repository(
        name = "com_google_cloud_go_workflows",
        importpath = "cloud.google.com/go/workflows",
        sum = "h1:phBz5TOAES0YGogxZ6Q7ISSudaf618lRhE3euzBpE9U=",
        version = "v1.14.2",
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
        name = "in_gopkg_yaml_v2",
        importpath = "gopkg.in/yaml.v2",
        sum = "h1:D8xgwECY7CYvx+Y2n4sBz93Jn9JRvxdiyyo8CTfuKaY=",
        version = "v2.4.0",
    )
    go_repository(
        name = "in_gopkg_yaml_v3",
        importpath = "gopkg.in/yaml.v3",
        sum = "h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=",
        version = "v3.0.1",
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
        sum = "h1:cH53jehLUN6UFLY71z+NDOiNJqDdPRaXzTel0sJySYA=",
        version = "v1.1.0",
    )
    go_repository(
        name = "io_opentelemetry_go_contrib_detectors_gcp",
        importpath = "go.opentelemetry.io/contrib/detectors/gcp",
        sum = "h1:F7q2tNlCaHY9nMKHR6XH9/qkp8FktLnIcy6jJNyOCQw=",
        version = "v1.36.0",
    )
    go_repository(
        name = "io_opentelemetry_go_contrib_instrumentation_google_golang_org_grpc_otelgrpc",
        importpath = "go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc",
        sum = "h1:rbRJ8BBoVMsQShESYZ0FkvcITu8X8QNwJogcLUmDNNw=",
        version = "v0.62.0",
    )
    go_repository(
        name = "io_opentelemetry_go_contrib_instrumentation_net_http_otelhttp",
        importpath = "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp",
        sum = "h1:Hf9xI/XLML9ElpiHVDNwvqI0hIFlzV8dgIr35kV1kRU=",
        version = "v0.62.0",
    )
    go_repository(
        name = "io_opentelemetry_go_otel",
        importpath = "go.opentelemetry.io/otel",
        sum = "h1:9zhNfelUvx0KBfu/gb+ZgeAfAgtWrfHJZcAqFC228wQ=",
        version = "v1.37.0",
    )
    go_repository(
        name = "io_opentelemetry_go_otel_metric",
        importpath = "go.opentelemetry.io/otel/metric",
        sum = "h1:mvwbQS5m0tbmqML4NqK+e3aDiO02vsf/WgbsdpcPoZE=",
        version = "v1.37.0",
    )
    go_repository(
        name = "io_opentelemetry_go_otel_sdk",
        importpath = "go.opentelemetry.io/otel/sdk",
        sum = "h1:ItB0QUqnjesGRvNcmAcU0LyvkVyGJ2xftD29bWdDvKI=",
        version = "v1.37.0",
    )
    go_repository(
        name = "io_opentelemetry_go_otel_sdk_metric",
        importpath = "go.opentelemetry.io/otel/sdk/metric",
        sum = "h1:90lI228XrB9jCMuSdA0673aubgRobVZFhbjxHHspCPc=",
        version = "v1.37.0",
    )
    go_repository(
        name = "io_opentelemetry_go_otel_trace",
        importpath = "go.opentelemetry.io/otel/trace",
        sum = "h1:HLdcFNbRQBE2imdSEgm/kwqmQj1Or1l/7bW6mxVK7z4=",
        version = "v1.37.0",
    )
    go_repository(
        name = "org_golang_google_api",
        importpath = "google.golang.org/api",
        sum = "h1:hUotakSkcwGdYUqzCRc5yGYsg4wXxpkKlW5ryVqvC1Y=",
        version = "v0.248.0",
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
        sum = "h1:ZERoum3uuqL0PRSc6SXielu26FN96T4BUGaaW0oL+c8=",
        version = "v0.0.0-20250818200422-3122310a409c",
    )
    go_repository(
        name = "org_golang_google_genproto_googleapis_api",
        importpath = "google.golang.org/genproto/googleapis/api",
        sum = "h1:AtEkQdl5b6zsybXcbz00j1LwNodDuH6hVifIaNqk7NQ=",
        version = "v0.0.0-20250818200422-3122310a409c",
    )
    go_repository(
        name = "org_golang_google_genproto_googleapis_bytestream",
        importpath = "google.golang.org/genproto/googleapis/bytestream",
        sum = "h1:CMCT63H4Rl6uNNT10m3hkjCR3JgAv4E9ZuVTeO+Sz98=",
        version = "v0.0.0-20250818200422-3122310a409c",
    )
    go_repository(
        name = "org_golang_google_genproto_googleapis_rpc",
        importpath = "google.golang.org/genproto/googleapis/rpc",
        sum = "h1:qXWI/sQtv5UKboZ/zUk7h+mrf/lXORyI+n9DKDAusdg=",
        version = "v0.0.0-20250818200422-3122310a409c",
    )
    go_repository(
        name = "org_golang_google_grpc",
        importpath = "google.golang.org/grpc",
        sum = "h1:+TW+dqTd2Biwe6KKfhE5JpiYIBWq865PhKGSXiivqt4=",
        version = "v1.75.0",
    )
    go_repository(
        name = "org_golang_google_protobuf",
        importpath = "google.golang.org/protobuf",
        sum = "h1:IgrO7UwFQGJdRNXH/sQux4R1Dj1WAKcLElzeeRaXV2A=",
        version = "v1.36.7",
    )
    go_repository(
        name = "org_golang_x_crypto",
        importpath = "golang.org/x/crypto",
        sum = "h1:WKYxWedPGCTVVl5+WHSSrOBT0O8lx32+zxmHxijgXp4=",
        version = "v0.41.0",
    )
    go_repository(
        name = "org_golang_x_mod",
        importpath = "golang.org/x/mod",
        sum = "h1:EGMPT//Ezu+ylkCijjPc+f4Aih7sZvaAr+O3EHBxvZg=",
        version = "v0.26.0",
    )
    go_repository(
        name = "org_golang_x_net",
        importpath = "golang.org/x/net",
        sum = "h1:lat02VYK2j4aLzMzecihNvTlJNQUq316m2Mr9rnM6YE=",
        version = "v0.43.0",
    )
    go_repository(
        name = "org_golang_x_oauth2",
        importpath = "golang.org/x/oauth2",
        sum = "h1:dnDm7JmhM45NNpd8FDDeLhK6FwqbOf4MLCM9zb1BOHI=",
        version = "v0.30.0",
    )
    go_repository(
        name = "org_golang_x_sync",
        importpath = "golang.org/x/sync",
        sum = "h1:ycBJEhp9p4vXvUZNszeOq0kGTPghopOL8q0fq3vstxw=",
        version = "v0.16.0",
    )
    go_repository(
        name = "org_golang_x_sys",
        importpath = "golang.org/x/sys",
        sum = "h1:vz1N37gP5bs89s7He8XuIYXpyY0+QlsKmzipCbUtyxI=",
        version = "v0.35.0",
    )
    go_repository(
        name = "org_golang_x_term",
        importpath = "golang.org/x/term",
        sum = "h1:O/2T7POpk0ZZ7MAzMeWFSg6S5IpWd/RXDlM9hgM3DR4=",
        version = "v0.34.0",
    )
    go_repository(
        name = "org_golang_x_text",
        importpath = "golang.org/x/text",
        sum = "h1:rhazDwis8INMIwQ4tpjLDzUhx6RlXqZNPEM0huQojng=",
        version = "v0.28.0",
    )
    go_repository(
        name = "org_golang_x_time",
        importpath = "golang.org/x/time",
        sum = "h1:ScB/8o8olJvc+CQPWrK3fPZNfh7qgwCrY0zJmoEQLSE=",
        version = "v0.12.0",
    )
    go_repository(
        name = "org_golang_x_tools",
        importpath = "golang.org/x/tools",
        sum = "h1:mBffYraMEf7aa0sB+NuKnuCy8qI/9Bughn8dC2Gu5r0=",
        version = "v0.35.0",
    )
    go_repository(
        name = "org_golang_x_xerrors",
        importpath = "golang.org/x/xerrors",
        sum = "h1:E7g+9GITq07hpfrRu66IVDexMakfv52eLZ2CXBWiKr4=",
        version = "v0.0.0-20191204190536-9bdfabe68543",
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
