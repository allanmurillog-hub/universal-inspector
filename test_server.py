from aiohttp import web
import asyncio

async def handle_sse(request):
    response = web.StreamResponse(
        status=200,
        reason='OK',
        headers={'Content-Type': 'text/event-stream'},
    )
    await response.prepare(request)
    for i in range(10):
        await asyncio.sleep(1)
        await response.write(f"data: {i}\n\n".encode('utf-8'))
    return response

async def handle_html(request):
    return web.Response(text="<html><body><h1>Test</h1><script>fetch('/sse');</script></body></html>", content_type='text/html')

app = web.Application()
app.router.add_get('/', handle_html)
app.router.add_get('/sse', handle_sse)

if __name__ == '__main__':
    web.run_app(app, port=8080)
