import android.content.Intent
import android.net.Uri
import android.webkit.WebView
open class OwnedBase
class Intake : OwnedBase() {
    lateinit var reader: WebView
    fun onCreate(intent: Intent) {
        val link = intent.data
        val destination = link?.getQueryParameter("destination")
        reader.loadUrl(destination!!)
    }
}
