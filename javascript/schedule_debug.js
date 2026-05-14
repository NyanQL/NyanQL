const now = new Date();

console.log(
  "[schedule_debug]",
  "executed_at=" + now.toISOString(),
  "job=" + nyanAllParams.nyan_job_name,
  "scheduled_at=" + nyanAllParams.nyan_schedule_time,
  "trigger=" + nyanAllParams.nyan_schedule_trigger
);

"schedule_debug executed at " + now.toISOString();
