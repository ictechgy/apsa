class Intake {
    DataClient loader;
    void record(Intent event) {
        loader.loadUrl(event.getDataString());
    }
    void onReceivedSslError(JobHandler task) {
        task.proceed();
    }
}
