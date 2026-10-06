class Help {
    lateinit var reader: WebView
    fun record(event: Intent, compact: Boolean) {
        val destination = "https://guide.example.test"
        if (compact) {
            val destination = event.getStringExtra("destination")
            audit.record(destination)
        }
        reader.loadUrl(destination)
    }
}
