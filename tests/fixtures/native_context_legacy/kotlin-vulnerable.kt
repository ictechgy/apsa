class Intake : AppCompatActivity() {
    lateinit var reader: WebView
    override fun onCreate(state: Bundle?) {
        val link = intent.data
        val destination = link?.getQueryParameter("destination")
        reader.loadUrl(destination!!)
    }
}
