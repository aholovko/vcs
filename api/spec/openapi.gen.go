// Package spec provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.11.0 DO NOT EDIT.
package spec

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	externalRef0 "github.com/trustbloc/vcs/pkg/restapi/v1/common"
)

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"H4sIAAAAAAAC/+x963Ibt9Lgq6C4WxW7lqTsXM75ov2ziiQnzLEtfbrYdSp2saAZkIQ1HEwAjGh+KW/t",
	"a+zr7ZNsoQHMADOYGyUqPif6lVjE4NLobvS9/xhFbJ2xlKRSjA7/GIloRdYY/vcoiogQV+yWpBdEZCwV",
	"RP05JiLiNJOUpaPD0RsWkwQtGEd6OILxyH4wHY1HGWcZ4ZISmBXDsLlUw+rTXa0I0iMQjEBUiJzE6GaL",
	"pPoplyvG6X9hNRwJwu8IV0vIbUZGhyMhOU2Xoy/jkTdwHhOJaSLqy12c/uf17OL0BG1WJEXBj1CGOV4T",
	"STiiAuWCxEgyxMnvOREStofTiCC2QBhFhEtMU3TMSUxSSXGC1M4QFigmC5qSGNEUXZIItv/D9OX05RTN",
	"JHpzfXmF3p5doRuiV2ByRfiGCgI/U4FwijDneKvWYTefSCTFuGHav6sxv128Ov7xux//9lFBh0qyhsP/",
	"d04Wo8PR9CBi6zVLp1u8Tv7bQYkAB+b2D45cSJwY6H0p4AxbUf+O5ilLowBaXMJNoIilCiDqfzGCoQp4",
	"9pSSoYgTLAnCKONMHW2BMiYEEUKdhC3QLdmiNZaEK1jCJRnI6ymjAtBBLDDbm5PPGeVEzGkA42apJEvC",
	"UUxSBrMqPEvogki6JgqugkQsjYXajfrJzOmsR/UMasG2ha7a53WxPjw5JwtOxKqNdMwQPcsYbVY0WqEI",
	"py7I2Q3gaEo23poiCEERsSxwvWfnV7Ozt0evx4guEIUriBSyMzgKfGQvqiTeKKEklf+zRO4xsvQXXBu2",
	"Ndd/Dh0WSMtAz2UWgckAer/nlJN4dPibz4O8hT6OR5LKRH0bYn/FxJoGR+PR54nES6EmZTSOvo/o6OOX",
	"8egouj3lnPFmvnkU3SLeyCSJ+rj+EcyJnL91H1XP5B3rdpfjXOjbHHqQkkDhn1VOFGY+xWozSdYhtqOI",
	"guOoytv9w1Qh4W6lCg99tuHggA2GQOL+XrvcO5IGAHnloLNiRQsa6WcOxgcpBH6Ze9NUZ/0lX+N0wgmO",
	"8U1C0NHl8WyGJPksFce9ozHw0TimajhOEE0XjK9h3XHBMbAQVEjYmPOyzRSxKWy8I4k6nuJpeRoTLiRO",
	"Y8tJYYtIrrBELIpyzoP0OR4B6fK55iULSgLYf5bZTeqVy7HBGV0YzmkcxtzZSTcJVScycAck8jFuPPoJ",
	"y2hVAqmRakqx6Wx2coxu1GcucA3zbCOouRnTn7Dq+6rRViPNlKs5tNNw2r50VPu8W8gEaP1Uh1Yj/2kS",
	"UH69PHuLxONIKcf3l1Jgu/QhRRXvajX4fExiKTlbjA5/+6O24/5Ypuet3PPoy8dBeGc314Z4Ax+08tNj",
	"li7oMudA3eIyzzLGJQlxi9QI3pqZ6R9viEAiI5HiDwXYXelfDQ3zTaGXEq4KEcDfBNN1QHF5xThaCzZf",
	"xyxCOI3RXfQ/RDz5tJHoLkIsTbZTdKa362F3ohg5W6AUr8nBHU5ygjJMuVCyIuEEERyt4MeSuwolZ6tt",
	"IHzDcn0ckeu52WJBuFY//FNOkZLQ9AJG/sQpCH5I5NHKgvJZqiXEGEusqDGPZM6JeD5GjHs6j/ORK6iW",
	"jNfBGNCJqH0Oe+s85eZPygn8mQVdKjjOcbKcw9nEXLRgjN18hAVBgqSCSnpHDNcRGjkMmI16mywZp3K1",
	"FiXmGHTJBVGCOlJbgL8bxdjnLQXx1oXpqubGt5lkS46zFY3mNxRe7PmayBWLH/BUK7ap4j8V6IblaWy1",
	"hfIZtwR0msaTa0E42qyY5bTq9D6GDTpuTEWW4G2QrOuKtUMLzCMivQkzGSpJ1e68gJujmcK7VdoGEpwu",
	"c7wkIcW8Cy/NIULnY1FYUfIYRcEajHpur8m+JRW7RdXC8Nvs8mz68j9evPxu8sPH4FOmhccAlJH73laX",
	"1V9pGFLhgG6M6JRMx+jTRs7vovknoZ5bjpI4m99FU3RCMqIlTZa6EwFpjuEv1etb5ByYEEnIWkFZH89u",
	"RBtr0hg9Y0bWTLbPUYa5pFGeYK75oEYC54LfHP3TrgBfO0K04ZlABqxAHP/7ICQZj0MycEF9WqFWXBm4",
	"teZGmvgUj4c9ri1fhsnU/22RWLE8iRU/Npsp9fP3OEmIHEZXIBCB6lxhGqVOce49aG2Yfq4mU2pQ+Qwr",
	"1PaVgH5vsJLIYG/PxPM+r3DwTWkwfrQjszZ+6JfPLExF2/uv2AOMcfGsHTnuIhmm9IAUYEg9JurlwNJD",
	"dTBaHjvk5tP7SspMHB4cqNdZchzdEj6lRC6mjC8PYhYdrOQ6OYg5XsiJ+vuE4VyuJnoHk7to8uJlp3Jl",
	"OIYj23XKZpaoy3d+2ir4aXWxIvedlA+CL3Hd4Oh2ydUDNY9Yoq0wtQtIWIQT0vDTknUh+ms1RqmoeB2e",
	"RCnoLcvnPAn8/UsIhvacDQBqhM/MSKW/UCEZ355gieso1zoccZJxIoDLVhhmIfKu9HDzBBum3Kr0hhR5",
	"l7jCpkRnAuBVDQpWIQlE/kMohjFFUOSMEwHLAAc5LQagEyxJo0FEwahhCgvw9glCT8isl/Uk42xBEzK/",
	"I1wEDUtmmnM9DplxYUMux6kw5rrQ/V2Vv/cyyPjoUJw0cM1BtlLB1cJ6MJyJXGhz+9Edpgm+SUgfC4aD",
	"rNeZutsWX9kd4XRB1cznmpIAZxyjUhuTedf6cRWm7UsF4ai336h7VyDVzxA20AS2P1WvzRBpnlRX09Fq",
	"clXzV6oOUUNLX4g2LBlHBXq/Imnx+PtexrEr0Za/KvkSp1vtRHEXNCOtJFR+Ijz3omHJXVzS0sScpKAp",
	"+hDuafc5Lb9t0Q1eOdK/90po0DX6dIzw2bWtX99fgVzZ8D4OtVnuYK7sZajEUUQyCQy/wb/ni52eVUd7",
	"v0R+I9RpUplsq94+zwipEaJEBm2y9N5nlDKJOJE5TxuA/2RZ7basdplRKwzzYwuVuFD1drnwyCdoFRru",
	"GgnYB3Ban7zUrLTuiGgaJXlMhFU8cXSbsk1C4iVIdi5P76UWeMD8GKbfnU2/TebpNvnSiKh1F8RFDxdo",
	"YGZrlwje20DU+QpvtVv2s5EEQZsURidkQTgnMSrkXWfCKboCexGYQdT/aGiW9mjLbhFdNOj/GyxQnoJr",
	"VDJE12sSUyxJstVgabFqU9HKcO3yJALrqLPyhsoV/FyczfnxNI0zRlM5RAhuJ4wqdu9OJ6eeKBA0yzj8",
	"3jWCqafQChJ1U2NLrFiyDHDC96cIJ8vSWD5g+roHPY3CK5A0epgVPm1u+4ALI0HTZUJQlt8kNIKHDyuZ",
	"8tf3/9C4tfMeKoijNjQG0Orjt2KPc+cPgTgt/rV2DNJm1M2KgNjb4VErZdaAS04J0I3cGwzJLFOfXb2+",
	"DOFjb79P0O2m9qKw67eLV8d//+Hl3z66e3W8P88UguuVntvB//HRcS8Yk23XuSw7UYyJpBGLqxwNMd4C",
	"DRAcf31/Zbfw48eBhpA0eiR4KXL9t4CXOdy8pNgquH5iLCE4Nc+Q1vfgtWynDjOhtsU5ET8usbjIb+zS",
	"YSaDZvpuiqdQcutxaVnZWQqY2R3h2yAc1d2oo5AF48SVREBx0YFLxJ3ulmxF3QmNjHJX3+4CJ8Ls1858",
	"9E8UrZggBRipDZHydw5LMa4UJIfX3uhLqUcahjhGA2GE778ne34Qo/ilxDIXrQKwgCH1p1oUnzZg+R8d",
	"z5KZwAwPnvrSGzL0WGeZbIop004Y9S0orZ4Q7h+z31m6jqC20vMUJyTjJMKSxMdsnTFBzmYnx98fz6r6",
	"ih01OgRSrByznGWKrgVBB3qFA2PlFQd/mP+bnXwp/v+dNul+OXDCLcUBYBeWZKLe/EmkNzVFpc1D/0kB",
	"0my1FaBt2tEF3iB16oRIUnWoQxyE4hNRLiRbm1D1kBGSxnNJ1lkSNqOfBAxPdrjabZonYNq1cK07au8I",
	"5zQm8yZ7+5kZYMIWWyYtmIgzq4m0mcdB5clO7WzehubENO63VEa4krPm6kiRVGyJxjgs5Z/roUgPReXQ",
	"Pis55rceSB24yNPP0QqnS+IlJxyzmPQwLhP9LUgXuVwheNoXnK1tMCm4LgPhV5Skco6FUH9jDVH3+lmB",
	"t8mGAcgNU4KAGCNBMsyxkUEw+jD63x9GKFphRVCEa41yQbmQIDhQ4YTKIywlEdoSr37VD5Y2RbWMPGfn",
	"anTYIlY5UEN4/aW2IhtpQUcFleHAuVzpiH9JvD1kWWJjlk1sTyhfBz17d3z5XB+cpcnWkdKK9/nDKOfp",
	"ISVycQh2bHEI93OoV5oU25+o7R9+2siJ/aWEw4eRTp5JY9ipE1Jl9rvOhfQPk2u2pRAMfTt9gY7K2SY/",
	"YXX8Y/3pUfmVOpgGUBvAg25LPdfsBDD03fGlNhc73DYcGZLN1Z56PEPFSOcp6iSinu9SyzxNZvFCvFvf",
	"lywbs7v2l+kkP5s77Hj5YVg/eA/zOv5MpHE3kthzX7SxvSWRUvufzJetb3HpA5xnjhOwvkDpWkSut1DN",
	"aO3Xo5utJJ22iKYVHQA2n7sNcObArZAT2cOBTl/U9cUsKAE7x/TlHZxutYX3y8cBoIrcZ7JcuQfQRNYb",
	"ajMj51nDa0NYzn0Cpd/kiaRZUtMZsXGtBEKh53EwEOXCAApu7pyTiSU3xbIVT3mVsM205LGXhN/RiCAc",
	"SYGwQGfn8OVG64LOQyaaBRsn9hh2RoztIMToMV0j+7s9vdGOgdvpgFNHitM2bQiLXmFhnGalFxkvpI6k",
	"jogQizxJtghHCgTASatZfZ0yrJHiu1ypPcS2aiR2S2aSc+nuD+1+aevJC7nITtQTXnFlCifgMWKpoDHh",
	"6sL1PLHLsGKl1Ei6Jh1bsEFbjaeBAR1BSEbDCIfDmB9DmokTPYA2K5oQHwkiBq4abR+mwpMlimTLsXWH",
	"GD3PuE6AprWEl6tH2hJnQDESYSuz5T49Wcc9TBY9Vzgu8fqReNTetdmvixZK5TeAx/bHwpKoJF1KEnDP",
	"lZNcaoV1ii6t/d6gGU2X/bhXaD8PqYyHFti/Xu6s+ieo6I9Hw/YR0bTaQ5e3H5roGv1diD4L+29/BaLC",
	"1A01EoE2ik/c0jSGoGn9whY+ZAhxZWhJ78CN/O74slUXNPufFyGeJp7XX/z64rUb1QEHMp9CVrAjTmAb",
	"u4+u8C0RSD3TChoRQQphjcI735AkuU3ZpgiiKYPEwER+w5QK1rJJzaKqk2EOCcvWWg6m+9TxvdvrKk6h",
	"TrahSVJYSzTXaxhJ0yLGJSMpjSeFBdIOOzw4aIN3sdM+ZSq0CHiwYglwR8ekAdhmTAfl4SOPGq4vXod3",
	"0vIQVdOP7v0k9coqGviCBjTiJcepbLAfGcqIcFp4a8wdw1c6qBrJFWf5clUJgDRRHeVARwIGE5SWe1zT",
	"QerXjIGEK8/yBHYFSL4CuVmSDEQYkuZr8NJ47EANHo0bLFCwLW12yjiZ4ELP0J997DDYBNHPpElCKFzI",
	"VWmgqYiPZfj3nFjzmvFd2VhTa6C7odp/pt6ciYlQcQ1dCiKWAxTRKPX1JEMYSIN8lkgQifIMxTnsOOPk",
	"jrJcGFBa/5qhDsV96B1ExOqjuSku+pLHiBpvngkuUv82DrwyrKZqZzP83B4/ACJtsLQQd+JmYSPTeqUd",
	"miLPNKPVxUXCNlp8ClyyAnVbGG0ROxumjSLmq+CQgOTmEuEY5HMGnEDpq0Yc10hvBAHrXKlguY3DQidk",
	"gfNEP0rVgjKdtV2K/cHvot/G3KjMOuWBW6jQaP39aaY+zE+eC8LnGW3zkve0CPRyplcO71qq9Our9oPO",
	"Z28RTpj61tKUrYVlakWlEOfq4pMBj9rKKCQD6teoeIzj4jVuDgtYJHgpHKu3PYgSTlI3eg6BfmgmVlyn",
	"zP/rIReGpbbdRL/hMt+/gqznW6v6+mcPwT/bJG3TVEiC4yn6+gxeD3zAP9tm9iS8PwnvdftC1Gn6/qql",
	"+XAhiGZz7UPT9ENYfB94TzsYyqb3sxrvD6i7GJ4feDf/mrbrJ2X2SZl9UmaflNknZfYvrczeV4vtzgfu",
	"o8Y2JUNBrTUn9iOseNiY27A47jw8hjOX7DHDQpFxQu7UW+Um31QYNAtMDrdeevBAGfnl6uoc/Xx6Bbwe",
	"/nFBYsrB16eXFWgNZbR0FvJ/XmgMcgR6y9hBqVMAVMip66Cp5xj0QLkilKM1u1Gk+75QaMPZiJ/DHncP",
	"LJb9OkqxCWzmnCRG4FmglJC4ITfaknTAPedTjAbbzyQlOkT07OocZVpnKmDbndEVxIxxPRatCWF3wfd3",
	"57YkTMUDDpLR9cXrS6WahKvbuDynLMDwiiaS8B5Foto+bpx9Foe3knPrmAk/KQFL0WuTnGSEQPdl0cWT",
	"hJtfY0qGlXYIQNpftIoqGdKxdNoV3ffRaGJh5lLa7vPOLBe6UZeDtdjQHHNdgMBmJ91RksHpzMcfG8/W",
	"VmkEaNYp6xGMEiv5sHkEWxMTGipvXhaqoVHlldy1MKHDAX2jPYijNZCIpujTRjzTQHyOGEefBEuT+Jme",
	"6bkxrYgdcsX3GqS19wip4zqYEVQCCqgr2qjZZT/x0cdkBfmEFsCwvowzPPu9k5GilXrt0mUI2Cuc4HQJ",
	"4j2OY1JU24Q6G01mLhzMz7xaERQ7Or2eQqlJbE2lYmliKyRZIyiWAbZB85p2mNPKdLN+dWXK5CmoeLnG",
	"oRf2BP4+4NyaI+qH/g0E8odBcH0xsxCof1KmaIchpDM8SPztDz+8/NHN8WYLdDI7Qc+M0MHKilons5Pn",
	"XdBsxk+LZD1RtKiSU3/QN7KlbwpdoLIEJCK/5zgRKNrIKbqky1SpJ++vlCJblHeBwoxFiZeGjPnBK35y",
	"Vvx1+IpQUDQbuqj+aope0/SWxAhq3gEQO5bvdK+USzVvaaqrAV0GKsLopdXnU3Scc67rU8h6uk05UJHL",
	"N5828ptuYdPZnPNUF/jTt0rAa1MmsZpgL+eSfJYNVQ9ph9UJZLCi1isGktVuIkd/UYqDU6QjYUsWKBMw",
	"K+ID28GhNuXAAY7Vr9YipBmdF1W6msQV0L8VEjnVul0VyanzpbS7nCax8XYwTsI2FfTs4tXx3/7+/Y/P",
	"tVKqWQ98ZAycWiE0oYTGSQh2AX8+sB9Om7LmaFjkNr8KEnESvuiazanZ2jNAYnZvzV/BzdKq7s+u5dxx",
	"9eJ6sthzTjLMu6sNlVKq+SLU72AP3SHMauUyP+Fw4FeTEj2wiqOeZtzVY6IBbMOADt5kxaCPGhSZrivQ",
	"7mhg8b6FdXjYwf5y1FoyAzsNue/KHFal2mg7z4dRxGLyYdRucX0gGgxlK/a6vodBhW7jXQ9caCxk5CFD",
	"c6aQZsXfiAoz9rkuaa4RVW18x/uVCq1yNKf+q5pP38tcyiRk0NLSalF3EpJntcPi6up1uEJelosViefB",
	"vQ6HzvnRRTtMejEsqEZoLHwE5VnE1nUHAG+r9FSzby8SthlE6FpCsWaP+FXCNqBnttpPikseN6HZuOC1",
	"Dbfan+KGWQxrT4qW8RJjqdjlNepBnj3eyQd9wgLQG/hOBWEFBw4ZkP1hSI3TKdUhvhNTkkb6OsNq7Qc1",
	"6MPIuLSMtzMuTOvGDRpE+GDuy4kmJd160Hj7HbNY6f6GJiCDukjsXil2hYHhNFRW/QV+Nf72QRAorLrz",
	"+9XOvbDzdBXRbaheXraFgFiEbgjt+Gbr5ccVvKrAt40eAKl35R4XRORJP3GtV2+wfdRpLXG0hvv/KqVY",
	"x6Coz5tOqJXLauHpMHVIHmi5c3VxfYrowo3XNAWHt0QibIup240bW/3Zue33q0NqwDJmPcNloKtkpnJn",
	"taCyjVGqlPcv4haehcpxqhf8eY8yX15GfgEQF4wWGm3EYfC7P3m0e9F8bIfMSzFQXne22rJWb3+TX1o+",
	"TMzuGHU7eSKbKlWEjNXe566d1pmr4zKLyT+GAdDjmiqnrrW1aap+6Ruw1kRiII+y8ZpjsuvZ1cYHnLbe",
	"/Yl9zAJtb0pz5e4PU49zebdZu5G+RJeLVUgd72NKyMWqojCaj5vl1K/LiNBUXqip3boL8Q64DQA/iYdr",
	"7vBZb229rVy8qcKf5usbCKjCstrnpigbb6Qwa3S9vpi5leShuG/GDC0Z5VhXxXK/KIvQC2QoKaYi4sQt",
	"bxsss3WTS/1Iym1GI5wkW50PkWC1YgKtwLhEz8h0OR2jGyI3hKToB4jW+duLF3ajz5uakWttPWiUrx4C",
	"9GoFbR3dG6oNViQ1MAFVCuGNB5CJojbyJBfQ4pxwYjoJVKpse+FC9QDMcIBhp5bnHtVr8V7B7ybE7OsS",
	"MRV7TKpO/QUX+ofTRvuITfJpN4aEC76ZTy0b7lHfclzbkAOPylkCTi5/xMwEezeeurcZu7Jy18Nhp/8Y",
	"3OKSCkk4mMd0tbaOru5l6bgielhNYaLkoRf78K7vl7owuG7dreeAODl9OeGy5mrUro3BnXGWwehVCx93",
	"TG7y5TK8eFf/+U6g9ieX2kSNr3D7vTS7U7QrKBzPUgGg6c0B3RiZF0GuzR3mjSgjEkgaT8CnZsLQPe7U",
	"lhIVZLnXF6/tFiCKd0NuUIaXxGnzXq+n3mHdAEE0km32BisDFm+gTsPaCm1Ohe9RRliWFN0YqIJWIf3p",
	"5cfOI0XWmCYIxzGHtq/DgqnLPI62XZfo4Gdw+PUh1cuTJGxT5JUUAa62VKU4RPVsizHaJdli2DE/bW5F",
	"U0HJb4QWUd6TG/QPskWXRKKYRTlo/aY1qrbOeU1tI/txGZwS7oqp1u7EQftK25iEKLi1Z7++/8dzb4O7",
	"bM3vvdi5NSOzGSlCSRcQAmBjd1roIWMJjbb9FoAXUei0k5XPKTJO73C0RXq68m4qmYK2dXJMsoRtYQTj",
	"S5yWyQhJotsV54KIMeIEIDYGAU7JiAkTRKCMcAGBqJCtEDbT6KhsdbA2qrHEYMfrnMlZwQMqECxzlMHW",
	"AyRVaH91snFIcRgteH7EflTvJavUCT/CKWSDmL82eN8CzGA4ITekrVwG2meJDEdkUpYTtj0SnIazzUep",
	"tc7qzHcWbCE3mIcDMI9QntLfc695t8F+0CfQ9fXs5DnCQuiYLJNsYDYVkzuSqHcWMY7sOpq4xYrwIhDf",
	"F54M3IGmPGuDxS07kX5v422K1+ZJ4UZUaPAOFEdtbHZ5ZPtbBg7so325jWIknOWDC9AGjzrcRuG20066",
	"dUNEYuExKKovh0oSF5vTJtA23E1ZSsbIC36ZK2Ws+rcbLGg0RW9ZSoo0PbWK4c16sEDPUlAzEc4yMbbZ",
	"Geofzy2HxynYfFf4DmpacyJFkUx1GFw0DDNxb4YsCV+D08QoAyVLrtxthUPrhEKltuRgSda5IWJFs0Kd",
	"9gQ909bCm80fADZroanVsh3/CW0PAm2Rie8lVneWdIYotZLMStMlJM6YZNCqFN4RORaslt3RtraYQFcA",
	"jIPFEa/oGpi7RkRX4iuJe4NF3aHoNvn7KlWDMqguCDz9szGuFMXW3XQwyKUuC2rYTfol31mIpXTuqrVe",
	"ZeOV6G+1IUtPoB6NF0qmoObPiovon1qv6kltelKbntSmJ7XpSW16Upue1KYntelJbfrLq01eCE89BcTT",
	"IlrxzJegPnYoZIMdHX2CA3s0VC1z0J+a84ay0kMtcfsBv2f4wiWR7jTaUSmxdKue98tCf0s2prLAtKNL",
	"wA7p3V1V8DpSsoOR08MTxIe0wLZkC8Bybq8T4Pe/OBvFVgkw72h7PjjS3J+v3xGHRBNeSsZ36qwnJOOD",
	"2+qxOJyk1JrB9Hj5FU5kU1EIzYK7FU73BPaAzmm7gL2lh1nX8YblfVxnMZakmrjfiEytw4ugHiF5HmnZ",
	"IlcfqNO/O25sSFsyh2BFkvvXIXCypBpW8PuodgfUlbPVvh375wns3sHRdvD3vMN3unMIOS/xgcQ9eYLt",
	"OqKL69VKhCmBLqPp9Knd5lO7za++3WaoMGYo6hxVsHxgYbBrpcgYoujiEuFKnYb4O+n2/vTfHXC7KwPo",
	"Wau9qMvhaXzeR061TKeYqH1Lirp1YPSPCAcu4mbTbDOCsDAFvaCy5qWx3f0wfTl9Cbheq7/J5IrwDYUG",
	"+doQXi8IPW6Y9u9qzG8Xr45//O7Hv30MVX7eT4x3tQSRzt1tzvgOmQoLo1rlss0HQyx7DZmZXqnHuLsi",
	"XinAFXuoJWt2Y3hfUilac/ppIk06XXvZJvjJlHgNZl22Fz5q/pA6Mbb9I2iLyNwv49HvOQkldDl046Xf",
	"/KcaHtBPK5elZy0ONnYA5GzavbhWeAfUYfhg6xSvXpHotikBSQ8O5og5tpQFpknOCYrUVMgwnVCJLhLd",
	"hu5ZfQXnaY7frX8GgbJoTYTAS7JzMat3blZU41ta1bXhIHZnwYWqN9QA8N55U9VJuor6OTfm7q67S2N7",
	"DfRdCvKhn3B0u8FcvXfrDEt6QxMqt+BzQmUn32MvN3RgBmrP0nZVKBa17dy2xMd/ckHCxl7HzsZa0GtY",
	"1csmiLTW47urcoV9l+N7oPp2X5qh1qdEXCvg+kiCBe/00m5FF4UqftG/dFEbu2lLa2080ECQeOmxHVwq",
	"a0pQDVR8HkLh7h6CNH7e2tLde7gfn87PG7q/N8D3HvczhNqzSnP7HeS4P5/gQ4e/B/yGEv0AfA9Qfae+",
	"EFWy5wfVO6umdAfmB3ln4J6y/pSm4R/04WTBZPnhJ3Jz5UNF+bmSZ8U9Cnllodz4+r2M7f2Ogxn2LZjW",
	"G1vfkyT5R8o26VlG0tmJTjk/bu/Z1P1NNcHXtB32RxiEBzkUC2Kc0e+OL7UZDvJ9Zyfnu5cGczqKnZ1/",
	"I1yzmWf1O20LyLzBMlq5tWp6rVcrMPCNqNckLNa1qbuvtX1ESbxqkpWUmUCAqtoA9Obon4X9NmNcjlGG",
	"5Qp+Ao3QseCUuO4W1R03VD+IGdHlRIylE4Y173dIy69KnYSyzPu5d6f93AgeComyFMGX8c7d6kP1YJrL",
	"Q7hmMHNtzAsagCg/Y9pJ8ZocODVIx6ayKsHRSoc2Q6Z2PcDJbK00O9fKEtkDxV2+7J2x9fHxtNOFbuHT",
	"WnqjV0eXlgvmRObA31F4bddKmtZdCIUx1fZ+MVzO6Xyk28NwdeXa8q8WM+vXiTXWcUql52GBEy80I9z/",
	"vqmb/1XDdXclCdyrVldbIEiFiHVBoQfht6HqRA+EyuN98dzWPYcLyokswdtejRU9/lNlW2YiVD612tJf",
	"3zi0Vys8AEpJz41trZcQ6dggzN7bo+vbiB1ivPUxvQhWy4Hh6S9e/Z8h7vdqWwtipdDd1S0B1F9y9aqR",
	"7Yyrb51ZvnokDW+2hydQ3ypOWbpds1zMdWxw5wVblu6wy0B7LhvSiCttt4Dd4mAPMF3vRa5YLhVG24wm",
	"7fm1jLed5bqRwwNE0RMdM2y9tRdu/HErRP0Y9IejDW/eByQP7Ut6uH3+ZuqwfwxGo1NhXfg77haCyOc2",
	"Fa8xXN52XMRIFB0UDLX++v6qZKp1giqy/Jwi9FjUAxObYrWHaDmaDlrRqTlA91531hYpLhy5FqL1qagF",
	"jZ+UtPdhlLLUFNTeoQxfL111iO/yC7gFF0wH5UHaGRSiWWOajA5HK5Ik7H9Jngt5k7BoGpO70XikozdH",
	"V+rPPyUsQpLg9RSajMJHiqEfHhz4n9WUmvJzUJINR3Z0g0I5UYzfq+Sn40bef3eM3h1Pjs5nbqdCDZnv",
	"30F9aMki5jZ8OrDWAjfqQ39X9gtMaESMfcuc9CjD0YpMvp2+qB1ys9lMMfw8ZXx5YL4VB69nx6dvL0/V",
	"N1P5WVuWat5Ll6JsASaI1tEmEh00NnoxVQuDw4ekOKOjw9F30xewF/UwAgodmPM5FvYDUUS1Zaw56k64",
	"IC9j6ZTYhG3ftNE5E06QqTARZ0URsJ9YvLUYRDRVO8FJB5+EFqq1zNQlUbUHr3358sV5N+B03754MWjx",
	"qjO6hpln/wCiE/l6jfm2C1J1mhoX17HkLM/EwR/w39nJl8D9HPyh/zs7+aI2twxl714QySm5M+FhPe7r",
	"ZxK8rsxpNvJbQ5fjn9VWTUgyVX9XOFYSvTnJyLUAaqdpDcClQbr+7ugTh5cQ5a/91/j46EjR41LaUMNh",
	"QOLAtH8uxUsdA2djzcL0e2o+CvaorcYCF9Xy68hi52kJat4HnXcu+wCkvuP65gXtgwW7XcIQ3Mh0leAJ",
	"CFUTJW0BlvzXxOntEEYQU1/YClHBviWu5OY0RvQaLATeAz1zQzeOfWBLr0Yge8aYfq0R+mBN364yO+GJ",
	"F8rR8PSbTNEiCNZhX1ZudcMl/S7+plG/cYT4LYCbUMXriLBPBCnXeSRsqFbvHnT/Xp+I3W96An6dh7tv",
	"mK5SKH3Hi6/3bdrj7VcXewAU2K11VmPsSX/cqDqsBmFILlYVWaLztajhiMlMdrvrQEEPEIa93uvaKOUx",
	"MCcgsoIWDYWg94UYHXWnmzGk65oaq3kPuSghGR8m9UGClrivzNeVxbaPq2hfc8/cuiOvrQ9h7gL5Ibhg",
	"cibIxLczd+CDDWIXjYkWuZNZ4mNBj1SRfSBC57J7xoXuuP8+6NAf8B1IYDL9xMEfRf7fF/1b7Dzxos06",
	"kPO6eRae5hVVHGZbv/pysB37ix46uifgB5pWnYjQwphsetvcbNGS3pEUGbDs4JOrnE3n+u7wJltlqQPE",
	"gdSQVpOL7Z3XZAlx80HvYW4ptiq9pHO7pk2/MItCE/5B83up/w2zVrJXWww5XZTxh58Z69vU4ENglj1M",
	"XSX4p3uHv7Oc2Xj7mmXe7yAbWPiNMBtwABU28VZaiO9LJgt10v9T7LqwERT1FbH7oaP3psPpBZngNJ7Y",
	"ugUTqzg94WmDCuL4wSVDFm6glcyCHiLXm0Mh6tI2UvETt0Q5WfHt9cVrp7SSzeR011XbUTquJ+c5uBig",
	"Jltiwg32A0ywvHhfpGXWVaD6/nj2SAJVZVVzVGfxbkp07xiZCULP7cOTaEGWjMbRE0n+hUjyr0CLg1Sa",
	"ChU+BvVxnWv8RHcNdFfSnIGUS2w6zkYNcykwrlt7mkpE7cvS01V1a9/Gno6SWCFauK1ae4j0q8hp6Fuw",
	"tZFBK/ZPNyRJJrcp26QHLCMpdZX8SRnoXKj67cnJVvm3U0EsUJ35ncHPPuuzkUOjPd5Ej4ScIfr3u+NL",
	"NDs5D2TgfMXqd4WJPDwPUainhJeDwgjVaCtqShoyALZlpA1TgLKfur5wUfi2Glrr1n+v4ByNo8K+1hV9",
	"8q6s6XRDkCDgavgA1ddMtFzAqOCFed7vkq5CTQCa1nVLhd5jzSNUZJCimPBK03EW20oBts8kxIOqDabN",
	"/RPHpoyvzbBDeKmELIkSLFsOxGIyd6tu3OtUpn4V7HmDy+I7+oz6ZMVi/bZU1lkdeKfBili2ErcO3ckF",
	"4RO8NJ0OvMLpbsnuwgeWcXJHWS6SLSJCYl19OTaJME1LmkYOTjksr0pzxhnQF+M6b3CNb+3wxqaVYYoo",
	"a5IPB5YOQrY9RTXFdyyoC3EPQ5AUsQz/nttCbl77iaLjxBpTnQIAdXy8wsDWS43TGEU4SW5wdKuViyDo",
	"i0bosux6Yep6m9s1kHYQQU3pY4NeoMw8uPzl7Pr1SaGcmMz+O9PKIeJMiImgstztgvGlKYcTBGRRrqg3",
	"IE9TRSRxmRnTnL8VsfSObIXJwdJ/c3pZOFZ49W9daBNtsKn8zG7UTUzRmzyRNEsaF3GUNU0NW4VOIHrM",
	"/UiC4gq9C6OpbjHNFmhtl6oYLUOgCxcNGwRKHf37jTDhw0q2SEkkbZz79cVrff/m39B2xCawxFRE7A7y",
	"UgwVA6+ThK9pShyAfqNAlGEoBUOJAPwtyrNP0cXp8dmbN6dvT05PFCSKpApXCG2lRVsfVYs/O9IkOK1W",
	"4OsvMeHN0T/huIocy3a6lvY0jmSSrul/kYKSvhGIfM4IpySNyAOcDkrnqY2NBsaaAuM1CYem/r12Qtmk",
	"L3NttnMA+SxtC4OKYYPwKToyU5Xty906c2U7lgwLoQu84dS1ioCG7TY8Ll78UtUrIW/SMHg1WM+taadW",
	"gk/MDLrymdmmx8jqp7kq14XyjBLfgumGKfbPcltt3ZZTU8umTKJljpVUSPQGGKdLmqqfzVmoaZ3Exyhi",
	"eRIrroBThKVUnLrhft3N73TFTkKVbqNftKPR+QLY60KgjlHtsxB6PloKZ3ZUzaTxRGe16T9PLJ/ANwkx",
	"9TM/jGwKNxFK2rVy5YdRPTG3YJlQVfCXq6vzS3QDRTKvL16HO2x/cFofQXnOlm7hRW4cTjjB8VY3GDDl",
	"SMtWXoCoZYcG24aI6pYZ3MREV75TWKFH/r//838FKjVglLCyFkirpD3XoBwNiQH/7sW3LYrs58lms5ks",
	"GF9Pcp4Q/Zb6mm24aHW4FGVIANH9WUhKioK07VgW+Bo0ItP3Cvq1J1uEF4AWgNrGV64EJirp0tpGORW3",
	"6hlNCL5t6FMSrv9YVNakC4NCMNBDSCXTm4IYFjmdFKm6rApnI59xZPO+OYlIRdvp26TBFjvt8vW9Ynka",
	"V6wIYDXoirMtGy8UanW1aEZzMM5VW6EJfVeiFG0cT6uCI0sDHxcp94rss4yzuxKRTtN4AmVj8wxUCLes",
	"zAJhXYQVHWk5XqfPef3GgFHrSU0Bupr+/jjRm5VVHslKWFu1sJSP/Vk3MuhoLlC0234FmNcS0BlAuj7o",
	"NtMIFfl4ZJNJdGp7pTyuTk4MX/be7/nRr/gRb7fvvdI4e2AD8QObg999+2QQ/ncxCLvlHB6NjRxFCnkT",
	"Ei/JmqT7CiI9im5bmcj3AeP3rRJ8vn9AbD6KbqEkb5uXFQaEOIZbeKKdZ2SYN99e0do1jW2mV1AMQ9rY",
	"lWxtT4GaCoDTGC2JLNXN64uZwoSy7R+oVY6VB4uyI6RVOnQIp2cosPPVFm53HpznYkXieyWZDRbyexag",
	"r5ne/s3NbkP6LDS6UgKNcj23w+HX4SDp2GZja8EdHB+t/Y/+unaswtz0NduwWvvBhqni39gZ1V7aJ5i2",
	"0u7vDTefCMO1w2/V1/bx5JgK96tZBSv1fGUug8ZucQ2lA//lPD7thrFqKITXzdR/ZkPms7r8/PJBUzBr",
	"YlyzvHzMCTYFFL9/8UOgyrR+ZN8yiY50Z20Y+vK7xma/6DSVVG7RFWPoNeZLAh98+2OAmTCG3uB0a+Eu",
	"QnK7Ps8uhkRje3Nl+VrOtBoQhtXeZN6GZiNHFV5vlAAYDbKMUlbzJME3CbFKabiRSXsP0tZ13KE9lqPx",
	"HDTTgJJ7YkygZTlmo9Q6Nb3AMJ1pBl5w58KPUUru7871ZNM+e2oU6AppI6yvQSlpxm1/5GC3l6zpuHaH",
	"5TFYStSLvmYcLA+2BJVbcFv0OM+XXtwjkEF9mStOqXb9Q+jnV7qfTrXykpENRX6zpnX/gtVLmasIcJYv",
	"V+jd8WWVGO8ylxjtI9scK6eI3Y6C21jhNE50I2Vb7rsMP1dPiVs1RUsBTD27OUEsN0VVihi9hrIJSvG9",
	"sFvrsFc5vT/L0i1O6nFTXNX9zFfWQ9sWxbJ74abvXgQZuQFIgB07wGphvQWZtJrA3Pb+cH+6AwcoQriI",
	"wNY/W29oYSerWgH0zbiu6BUWRqlXeid48UQOSy7ypAG5wxgCtL2/F6FFu7cOwrH1EJZudvAeOwzVluRr",
	"dHr24Z5hr2uDt7TuWLzXuvOiuUDINMG3mWRLjrOVUZU5TmO29rrnO+qtZeWkWZGygr00vrpC9uvcbVlh",
	"uLeq5RuTWhSvXg0wPbSwXwCL67P9dtW5hnIfvA9qvmnz5MUddiBF33JFKLdlVy2ItHUl0j7Rzr3Lz4NB",
	"opfW34W86Y4CcLZY9ELYijrg4MPH/g/2A9nEFUMDBtWVfFQY4ytF73GMStt+jeF7BZHbuX6ro03bPDRx",
	"P+Ueea+tBoxAsdZI9fuXOsV4DdMv2Pu748tGVhuSb/QC2nWxJweRXQQ2rVdqdRi93O/KPRXeF/vcRaev",
	"qoPy7JQGEYrrC1OgEZdaibBR+B5QnNZs2Mnz6l3s9BELcNQp+sEJ+iEKczxexdW+cRtwq0d3mMLz1/2k",
	"BF2/bxkyGFXB65+JLOR6jWCVVqJuHIFNVoVAggbWCQKoKZIWo2fmExI/by+/8TOxCExiL5TkCY0fAY0f",
	"/vUJ3+cF+X3f4lfTwiLrGVjTG4HrVKG4vlWZ/DTvai3CsoVg2BAKDTyfzKBPZtAnM+jWqQZQWDndUhd+",
	"QQ7tzfKCgUHlDNtFne6JzcT7h/wMtesTTNeOwFaVwnTo/8z5Esob76GgHOzELSjnSom5bXexQ53/LjAv",
	"ibRFFwo7nnGmGwuzW/dkGgZ015t+Ap7sslRb+IE1ZdoGRgUWFzy8tJpuidutLJ9YR3wBRbd+396Ek3eV",
	"1dDdI+jN9RJq1Y7S+6qhFuyAvu+6mU3dsnuVy6z2T+/BhfZfzemvi6xFnSAaRw7PfoxaSO/OHwNbK0sO",
	"QtZHf2/7Ybq7ygMw5D8Fxf8Mduw1l98nP671qX8UjhzsmT2AJ2c+eEK4qj4Dg67GsLIH1uHBQcIinKyY",
	"kIf/8eLvL0bqQswUVZzQHuqJdoPFaM1iklSCoqr5wKM6Ztl99ZynOEbAk63j8FYEJ3KFoDt5+Z3+q/7j",
	"l49f/n8AAAD//yDSkvwoNwEA",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %s", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}

	return buf.Bytes(), nil
}

var rawSpec = decodeSpecCached()

// a naive cached of a decoded swagger spec
func decodeSpecCached() func() ([]byte, error) {
	data, err := decodeSpec()
	return func() ([]byte, error) {
		return data, err
	}
}

// Constructs a synthetic filesystem for resolving external references when loading openapi specifications.
func PathToRawSpec(pathToFile string) map[string]func() ([]byte, error) {
	var res = make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	pathPrefix := path.Dir(pathToFile)

	for rawPath, rawFunc := range externalRef0.PathToRawSpec(path.Join(pathPrefix, "./common.yaml")) {
		if _, ok := res[rawPath]; ok {
			// it is not possible to compare functions in golang, so always overwrite the old value
		}
		res[rawPath] = rawFunc
	}
	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	var resolvePath = PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		var pathToFile = url.String()
		pathToFile = path.Clean(pathToFile)
		getSpec, ok := resolvePath[pathToFile]
		if !ok {
			err1 := fmt.Errorf("path not found: %s", pathToFile)
			return nil, err1
		}
		return getSpec()
	}
	var specData []byte
	specData, err = rawSpec()
	if err != nil {
		return
	}
	swagger, err = loader.LoadFromData(specData)
	if err != nil {
		return
	}
	return
}
