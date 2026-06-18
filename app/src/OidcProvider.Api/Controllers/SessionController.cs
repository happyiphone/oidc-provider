using Microsoft.AspNetCore.Mvc;

namespace OidcProvider.Api.Controllers;

// OpenID Connect Session Management 1.0 — the check_session_iframe. The RP embeds this OP-origin
// iframe and postMessages "<client_id> <session_state>"; we recompute session_state from the opbs
// cookie (read same-origin in this iframe) and reply "changed"/"unchanged"/"error". (Cross-site
// cookie access in the embedded iframe needs SameSite=None+Secure in production.)
public sealed class SessionController : Controller
{
    [HttpGet("/connect/check_session")]
    public IActionResult CheckSession() => Content(CheckSessionHtml, "text/html");

    private const string CheckSessionHtml = @"<!doctype html><html><head><meta charset=utf-8><title>check_session</title></head><body><script>
function b64u(buf){let s='';for(const x of new Uint8Array(buf))s+=String.fromCharCode(x);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
function cookie(name){return (document.cookie.match('(?:^|; )'+name+'=([^;]*)')||[])[1]||'';}
window.addEventListener('message', async function(e){
  try{
    const parts = String(e.data).split(' ');
    const clientId = parts[0], received = parts[1] || '';
    const opbs = cookie('opbs');
    const salt = received.split('.')[1] || '';
    const data = clientId + ' ' + e.origin + ' ' + opbs + ' ' + salt;
    const hash = b64u(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data)));
    const expected = hash + '.' + salt;
    e.source.postMessage(expected === received ? 'unchanged' : 'changed', e.origin);
  }catch(err){ e.source.postMessage('error', e.origin); }
});
</script></body></html>";
}
