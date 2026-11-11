"""Single source of truth for the six independently deployed frontends."""
FRONTEND_PORTS={'magalu:web': 8181, 'magalu:app': 8182, 'netshoes:web': 8183, 'netshoes:app': 8184, 'magalupay:web': 8185, 'magalupay:app': 8186}

def callback_uri(client_key):
    return f"http://localhost:{FRONTEND_PORTS[client_key]}/callback"
