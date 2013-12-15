m_html5
=======

A proof of concept module for Unreal IRCd that allows clients to connect through HTML5 WebSockets as well as normal connections

Important information (applies to v0.1)
=======
This version requires you to modify the unrealircd source code, because the hook "HOOKTYPE_RAWPACKET_IN" does not support an OUT parameter for buffer length.

Search your s_bsd.c for 

    int v = (*(h->func.intfunc))(cptr, readbuf, length);
    
and replace it with

    int v = (*(h->func.intfunc))(cptr, readbuf, &length);
    
I've submitted a bug report here:
http://bugs.unrealircd.org/view.php?id=4250

However, as of the first commit it has not yet been patched.
