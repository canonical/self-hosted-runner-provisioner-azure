import azure.functions as func

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)


def no_runner(body: str) -> func.HttpResponse:
    """HTTP response if no runner provisioned

    (and webhook successfully processed)
    """
    return func.HttpResponse(
        body,
        status_code=230,  # Custom status code for easier monitoring from GitHub webhook logs
    )


@app.route(route="job_queued", trigger_arg_name="request")
def job_queued(request: func.HttpRequest) -> func.HttpResponse:
    # TODO: validate https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
    if request.headers.get("X-GitHub-Event") != "workflow_job":
        return func.HttpResponse("Invalid GitHub event", status_code=400)
    try:
        body = request.get_json()
    except ValueError:
        return func.HttpResponse("No valid JSON data", status_code=400)
    if body["action"] != "queued":
        return no_runner('action != "queued"')
    labels = body["workflow_job"]["labels"]
    for required_label in (
        "self-hosted",
        "data-platform",
        "ubuntu",
        "ARM64",
        "4cpu16ram",
    ):
        if required_label not in labels:
            return no_runner(f"{required_label=} missing from {labels=}")
    # TODO: provision runner
    return func.HttpResponse("Runner provisioned", status_code=200)
