import azure.functions as func

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)


def no_runner(body: str) -> func.HttpResponse:
    """HTTP response if no runner provisioned
    
    (and webhook successfully processed)
    """
    return func.HttpResponse(body, status_code=230)


@app.route(route="job_queued")
def job_queued(req: func.HttpRequest) -> func.HttpResponse:
    # TODO: validate https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
    if req.headers.get("X-GitHub-Event") != "workflow_job":
        return func.HttpResponse("Invalid GitHub event", status_code=400)
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse("No valid JSON data", status_code=400)
    if body["action"] != "queued":
        return no_runner('action != "queued"')
    labels = body["workflow_job"]["labels"]
    for required_label in ("self-hosted", "data-platform", "ubuntu", "ARM64"):
        if required_label not in labels:
            return no_runner(f"{required_label=} missing from {labels=}")
    # TODO: provision runner
    return func.HttpResponse("Runner provisioned", status_code=200)
