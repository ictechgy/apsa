class Intake : AppCompatActivity() {
    lateinit var reader: WebView
    override fun onCreate(state: Bundle?) {
        val link = intent.data
        val destination = link?.getQueryParameter("destination")
        val parsed = Uri.parse(destination)
        if (parsed.scheme == "https" && parsed.host == "guide.example.test") {
            reader.loadUrl(destination!!)
        }
    }
}
