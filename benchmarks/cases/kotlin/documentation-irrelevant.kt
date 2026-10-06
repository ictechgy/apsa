class Help {
    lateinit var reader: WebView
    fun show() {
        // reader.loadUrl(intent.data!!.toString())
        val sample = "reader.loadUrl(getIntent().getDataString()); handler.proceed()"
        reader.loadUrl("https://guide.example.test")
    }
}
