`logLevel`
- See https://learn.microsoft.com/en-us/azure/azure-functions/configure-monitoring
- `default` appears to apply to all logs except `Host.Aggregator`, `Host.Results`, and `Function`—which have their own defaults
- Explicity include `default`—the docs say it defaults to `Warning`, but we've observed information level logs when `default` was unset
- This config disables the automatic logs for the beginning/end of function execution (only for `job` function), but still shows `Information` logs that we choose to log in [function_app.py](function_app.py)
  ```json
  "Function": "Information",
  "Function.job": "Warning",
  "Function.job.User": "Information"
  ```
- It is not possible to disable performance counter logs via `logLevel`, so we use `enablePerformanceCountersCollection`
