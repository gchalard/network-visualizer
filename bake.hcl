group "default" {
    targets = [
        "frontend"
    ]
}

target "frontend" {
    context = "src/app/frontend"
    dockerfile = "Dockerfile"

    tags = [
        "ghcr.io/gchalard/nw-scanner-front:latest"
    ]
}
