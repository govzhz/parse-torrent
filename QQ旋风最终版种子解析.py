import requests
import re
import execjs
import json
from contextlib import closing
from requests.exceptions import ConnectionError

"""
For the readability of the code, I write the code of parse password in here and we will use it in step 2
JS parse:
"""
ctx = execjs.compile(r"""
var navigator = navigator||{};
var window = window||{};
RSA = function() {
    function t(t, e) {
        return new a(t, e)
    }
    function e(t, e) {
        if (e < t.length + 11) return uv_alert("Message too long for RSA"),
        null;
        for (var i = new Array,
        n = t.length - 1; n >= 0 && e > 0;) {
            var r = t.charCodeAt(n--);
            i[--e] = r
        }
        i[--e] = 0;
        for (var o = new Y,
        s = new Array; e > 2;) {
            for (s[0] = 0; 0 == s[0];) o.nextBytes(s);
            i[--e] = s[0]
        }
        return i[--e] = 2,
        i[--e] = 0,
        new a(i)
    }
    function i() {
        this.n = null,
        this.e = 0,
        this.d = null,
        this.p = null,
        this.q = null,
        this.dmp1 = null,
        this.dmq1 = null,
        this.coeff = null
    }
    function n(e, i) {
        null != e && null != i && e.length > 0 && i.length > 0 ? (this.n = t(e, 16), this.e = parseInt(i, 16)) : uv_alert("Invalid RSA public key")
    }
    function r(t) {
        return t.modPowInt(this.e, this.n)
    }
    function o(t) {
        var i = e(t, this.n.bitLength() + 7 >> 3);
        if (null == i) return null;
        var n = this.doPublic(i);
        if (null == n) return null;
        var r = n.toString(16);
        return 0 == (1 & r.length) ? r: "0" + r
    }
    function a(t, e, i) {
        null != t && ("number" == typeof t ? this.fromNumber(t, e, i) : null == e && "string" != typeof t ? this.fromString(t, 256) : this.fromString(t, e))
    }
    function s() {
        return new a(null)
    }
    function p(t, e, i, n, r, o) {
        for (; --o >= 0;) {
            var a = e * this[t++] + i[n] + r;
            r = Math.floor(a / 67108864),
            i[n++] = 67108863 & a
        }
        return r
    }
    function c(t, e, i, n, r, o) {
        for (var a = 32767 & e,
        s = e >> 15; --o >= 0;) {
            var p = 32767 & this[t],
            c = this[t++] >> 15,
            u = s * p + c * a;
            p = a * p + ((32767 & u) << 15) + i[n] + (1073741823 & r),
            r = (p >>> 30) + (u >>> 15) + s * c + (r >>> 30),
            i[n++] = 1073741823 & p
        }
        return r
    }
    function u(t, e, i, n, r, o) {
        for (var a = 16383 & e,
        s = e >> 14; --o >= 0;) {
            var p = 16383 & this[t],
            c = this[t++] >> 14,
            u = s * p + c * a;
            p = a * p + ((16383 & u) << 14) + i[n] + r,
            r = (p >> 28) + (u >> 14) + s * c,
            i[n++] = 268435455 & p
        }
        return r
    }
    function l(t) {
        return lt.charAt(t)
    }
    function h(t, e) {
        var i = ht[t.charCodeAt(e)];
        return null == i ? -1 : i
    }
    function f(t) {
        for (var e = this.t - 1; e >= 0; --e) t[e] = this[e];
        t.t = this.t,
        t.s = this.s
    }
    function g(t) {
        this.t = 1,
        this.s = 0 > t ? -1 : 0,
        t > 0 ? this[0] = t: -1 > t ? this[0] = t + DV: this.t = 0
    }
    function m(t) {
        var e = s();
        return e.fromInt(t),
        e
    }
    function d(t, e) {
        var i;
        if (16 == e) i = 4;
        else if (8 == e) i = 3;
        else if (256 == e) i = 8;
        else if (2 == e) i = 1;
        else if (32 == e) i = 5;
        else {
            if (4 != e) return void this.fromRadix(t, e);
            i = 2
        }
        this.t = 0,
        this.s = 0;
        for (var n = t.length,
        r = !1,
        o = 0; --n >= 0;) {
            var s = 8 == i ? 255 & t[n] : h(t, n);
            0 > s ? "-" == t.charAt(n) && (r = !0) : (r = !1, 0 == o ? this[this.t++] = s: o + i > this.DB ? (this[this.t - 1] |= (s & (1 << this.DB - o) - 1) << o, this[this.t++] = s >> this.DB - o) : this[this.t - 1] |= s << o, o += i, o >= this.DB && (o -= this.DB))
        }
        8 == i && 0 != (128 & t[0]) && (this.s = -1, o > 0 && (this[this.t - 1] |= (1 << this.DB - o) - 1 << o)),
        this.clamp(),
        r && a.ZERO.subTo(this, this)
    }
    function _() {
        for (var t = this.s & this.DM; this.t > 0 && this[this.t - 1] == t;)--this.t
    }
    function v(t) {
        if (this.s < 0) return "-" + this.negate().toString(t);
        var e;
        if (16 == t) e = 4;
        else if (8 == t) e = 3;
        else if (2 == t) e = 1;
        else if (32 == t) e = 5;
        else {
            if (4 != t) return this.toRadix(t);
            e = 2
        }
        var i, n = (1 << e) - 1,
        r = !1,
        o = "",
        a = this.t,
        s = this.DB - a * this.DB % e;
        if (a-->0) for (s < this.DB && (i = this[a] >> s) > 0 && (r = !0, o = l(i)); a >= 0;) e > s ? (i = (this[a] & (1 << s) - 1) << e - s, i |= this[--a] >> (s += this.DB - e)) : (i = this[a] >> (s -= e) & n, 0 >= s && (s += this.DB, --a)),
        i > 0 && (r = !0),
        r && (o += l(i));
        return r ? o: "0"
    }
    function y() {
        var t = s();
        return a.ZERO.subTo(this, t),
        t
    }
    function w() {
        return this.s < 0 ? this.negate() : this
    }
    function b(t) {
        var e = this.s - t.s;
        if (0 != e) return e;
        var i = this.t;
        if (e = i - t.t, 0 != e) return e;
        for (; --i >= 0;) if (0 != (e = this[i] - t[i])) return e;
        return 0
    }
    function A(t) {
        var e, i = 1;
        return 0 != (e = t >>> 16) && (t = e, i += 16),
        0 != (e = t >> 8) && (t = e, i += 8),
        0 != (e = t >> 4) && (t = e, i += 4),
        0 != (e = t >> 2) && (t = e, i += 2),
        0 != (e = t >> 1) && (t = e, i += 1),
        i
    }
    function q() {
        return this.t <= 0 ? 0 : this.DB * (this.t - 1) + A(this[this.t - 1] ^ this.s & this.DM)
    }
    function k(t, e) {
        var i;
        for (i = this.t - 1; i >= 0; --i) e[i + t] = this[i];
        for (i = t - 1; i >= 0; --i) e[i] = 0;
        e.t = this.t + t,
        e.s = this.s
    }
    function C(t, e) {
        for (var i = t; i < this.t; ++i) e[i - t] = this[i];
        e.t = Math.max(this.t - t, 0),
        e.s = this.s
    }
    function $(t, e) {
        var i, n = t % this.DB,
        r = this.DB - n,
        o = (1 << r) - 1,
        a = Math.floor(t / this.DB),
        s = this.s << n & this.DM;
        for (i = this.t - 1; i >= 0; --i) e[i + a + 1] = this[i] >> r | s,
        s = (this[i] & o) << n;
        for (i = a - 1; i >= 0; --i) e[i] = 0;
        e[a] = s,
        e.t = this.t + a + 1,
        e.s = this.s,
        e.clamp()
    }
    function T(t, e) {
        e.s = this.s;
        var i = Math.floor(t / this.DB);
        if (i >= this.t) return void(e.t = 0);
        var n = t % this.DB,
        r = this.DB - n,
        o = (1 << n) - 1;
        e[0] = this[i] >> n;
        for (var a = i + 1; a < this.t; ++a) e[a - i - 1] |= (this[a] & o) << r,
        e[a - i] = this[a] >> n;
        n > 0 && (e[this.t - i - 1] |= (this.s & o) << r),
        e.t = this.t - i,
        e.clamp()
    }
    function S(t, e) {
        for (var i = 0,
        n = 0,
        r = Math.min(t.t, this.t); r > i;) n += this[i] - t[i],
        e[i++] = n & this.DM,
        n >>= this.DB;
        if (t.t < this.t) {
            for (n -= t.s; i < this.t;) n += this[i],
            e[i++] = n & this.DM,
            n >>= this.DB;
            n += this.s
        } else {
            for (n += this.s; i < t.t;) n -= t[i],
            e[i++] = n & this.DM,
            n >>= this.DB;
            n -= t.s
        }
        e.s = 0 > n ? -1 : 0,
        -1 > n ? e[i++] = this.DV + n: n > 0 && (e[i++] = n),
        e.t = i,
        e.clamp()
    }
    function D(t, e) {
        var i = this.abs(),
        n = t.abs(),
        r = i.t;
        for (e.t = r + n.t; --r >= 0;) e[r] = 0;
        for (r = 0; r < n.t; ++r) e[r + i.t] = i.am(0, n[r], e, r, 0, i.t);
        e.s = 0,
        e.clamp(),
        this.s != t.s && a.ZERO.subTo(e, e)
    }
    function x(t) {
        for (var e = this.abs(), i = t.t = 2 * e.t; --i >= 0;) t[i] = 0;
        for (i = 0; i < e.t - 1; ++i) {
            var n = e.am(i, e[i], t, 2 * i, 0, 1); (t[i + e.t] += e.am(i + 1, 2 * e[i], t, 2 * i + 1, n, e.t - i - 1)) >= e.DV && (t[i + e.t] -= e.DV, t[i + e.t + 1] = 1)
        }
        t.t > 0 && (t[t.t - 1] += e.am(i, e[i], t, 2 * i, 0, 1)),
        t.s = 0,
        t.clamp()
    }
    function E(t, e, i) {
        var n = t.abs();
        if (! (n.t <= 0)) {
            var r = this.abs();
            if (r.t < n.t) return null != e && e.fromInt(0),
            void(null != i && this.copyTo(i));
            null == i && (i = s());
            var o = s(),
            p = this.s,
            c = t.s,
            u = this.DB - A(n[n.t - 1]);
            u > 0 ? (n.lShiftTo(u, o), r.lShiftTo(u, i)) : (n.copyTo(o), r.copyTo(i));
            var l = o.t,
            h = o[l - 1];
            if (0 != h) {
                var f = h * (1 << this.F1) + (l > 1 ? o[l - 2] >> this.F2: 0),
                g = this.FV / f,
                m = (1 << this.F1) / f,
                d = 1 << this.F2,
                _ = i.t,
                v = _ - l,
                y = null == e ? s() : e;
                for (o.dlShiftTo(v, y), i.compareTo(y) >= 0 && (i[i.t++] = 1, i.subTo(y, i)), a.ONE.dlShiftTo(l, y), y.subTo(o, o); o.t < l;) o[o.t++] = 0;
                for (; --v >= 0;) {
                    var w = i[--_] == h ? this.DM: Math.floor(i[_] * g + (i[_ - 1] + d) * m);
                    if ((i[_] += o.am(0, w, i, v, 0, l)) < w) for (o.dlShiftTo(v, y), i.subTo(y, i); i[_] < --w;) i.subTo(y, i)
                }
                null != e && (i.drShiftTo(l, e), p != c && a.ZERO.subTo(e, e)),
                i.t = l,
                i.clamp(),
                u > 0 && i.rShiftTo(u, i),
                0 > p && a.ZERO.subTo(i, i)
            }
        }
    }
    function R(t) {
        var e = s();
        return this.abs().divRemTo(t, null, e),
        this.s < 0 && e.compareTo(a.ZERO) > 0 && t.subTo(e, e),
        e
    }
    function B(t) {
        this.m = t
    }
    function M(t) {
        return t.s < 0 || t.compareTo(this.m) >= 0 ? t.mod(this.m) : t
    }
    function I(t) {
        return t
    }
    function V(t) {
        t.divRemTo(this.m, null, t)
    }
    function j(t, e, i) {
        t.multiplyTo(e, i),
        this.reduce(i)
    }
    function L(t, e) {
        t.squareTo(e),
        this.reduce(e)
    }
    function N() {
        if (this.t < 1) return 0;
        var t = this[0];
        if (0 == (1 & t)) return 0;
        var e = 3 & t;
        return e = e * (2 - (15 & t) * e) & 15,
        e = e * (2 - (255 & t) * e) & 255,
        e = e * (2 - ((65535 & t) * e & 65535)) & 65535,
        e = e * (2 - t * e % this.DV) % this.DV,
        e > 0 ? this.DV - e: -e
    }
    function F(t) {
        this.m = t,
        this.mp = t.invDigit(),
        this.mpl = 32767 & this.mp,
        this.mph = this.mp >> 15,
        this.um = (1 << t.DB - 15) - 1,
        this.mt2 = 2 * t.t
    }
    function Q(t) {
        var e = s();
        return t.abs().dlShiftTo(this.m.t, e),
        e.divRemTo(this.m, null, e),
        t.s < 0 && e.compareTo(a.ZERO) > 0 && this.m.subTo(e, e),
        e
    }
    function H(t) {
        var e = s();
        return t.copyTo(e),
        this.reduce(e),
        e
    }
    function z(t) {
        for (; t.t <= this.mt2;) t[t.t++] = 0;
        for (var e = 0; e < this.m.t; ++e) {
            var i = 32767 & t[e],
            n = i * this.mpl + ((i * this.mph + (t[e] >> 15) * this.mpl & this.um) << 15) & t.DM;
            for (i = e + this.m.t, t[i] += this.m.am(0, n, t, e, 0, this.m.t); t[i] >= t.DV;) t[i] -= t.DV,
            t[++i]++
        }
        t.clamp(),
        t.drShiftTo(this.m.t, t),
        t.compareTo(this.m) >= 0 && t.subTo(this.m, t)
    }
    function U(t, e) {
        t.squareTo(e),
        this.reduce(e)
    }
    function P(t, e, i) {
        t.multiplyTo(e, i),
        this.reduce(i)
    }
    function O() {
        return 0 == (this.t > 0 ? 1 & this[0] : this.s)
    }
    function Z(t, e) {
        if (t > 4294967295 || 1 > t) return a.ONE;
        var i = s(),
        n = s(),
        r = e.convert(this),
        o = A(t) - 1;
        for (r.copyTo(i); --o >= 0;) if (e.sqrTo(i, n), (t & 1 << o) > 0) e.mulTo(n, r, i);
        else {
            var p = i;
            i = n,
            n = p
        }
        return e.revert(i)
    }
    function W(t, e) {
        var i;
        return i = 256 > t || e.isEven() ? new B(e) : new F(e),
        this.exp(t, i)
    }
    function X(t) {
        gt[mt++] ^= 255 & t,
        gt[mt++] ^= t >> 8 & 255,
        gt[mt++] ^= t >> 16 & 255,
        gt[mt++] ^= t >> 24 & 255,
        mt >= vt && (mt -= vt)
    }
    function G() {
        X((new Date).getTime())
    }
    function J() {
        if (null == ft) {
            for (G(), ft = nt(), ft.init(gt), mt = 0; mt < gt.length; ++mt) gt[mt] = 0;
            mt = 0
        }
        return ft.next()
    }
    function K(t) {
        var e;
        for (e = 0; e < t.length; ++e) t[e] = J()
    }
    function Y() {}
    function tt() {
        this.i = 0,
        this.j = 0,
        this.S = new Array
    }
    function et(t) {
        var e, i, n;
        for (e = 0; 256 > e; ++e) this.S[e] = e;
        for (i = 0, e = 0; 256 > e; ++e) i = i + this.S[e] + t[e % t.length] & 255,
        n = this.S[e],
        this.S[e] = this.S[i],
        this.S[i] = n;
        this.i = 0,
        this.j = 0
    }
    function it() {
        var t;
        return this.i = this.i + 1 & 255,
        this.j = this.j + this.S[this.i] & 255,
        t = this.S[this.i],
        this.S[this.i] = this.S[this.j],
        this.S[this.j] = t,
        this.S[t + this.S[this.i] & 255]
    }
    function nt() {
        return new tt
    }
    function rt(t, e, n) {
        e = "F20CE00BAE5361F8FA3AE9CEFA495362FF7DA1BA628F64A347F0A8C012BF0B254A30CD92ABFFE7A6EE0DC424CB6166F8819EFA5BCCB20EDFB4AD02E412CCF579B1CA711D55B8B0B3AEB60153D5E0693A2A86F3167D7847A0CB8B00004716A9095D9BADC977CBB804DBDCBA6029A9710869A453F27DFDDF83C016D928B3CBF4C7",
        n = "3";
        var r = new i;
        return r.setPublic(e, n),
        r.encrypt(t)
    }
    i.prototype.doPublic = r,
    i.prototype.setPublic = n,
    i.prototype.encrypt = o;
    var ot, at = 0xdeadbeefcafe,
    st = 15715070 == (16777215 & at);
    st && "Microsoft Internet Explorer" == navigator.appName ? (a.prototype.am = c, ot = 30) : st && "Netscape" != navigator.appName ? (a.prototype.am = p, ot = 26) : (a.prototype.am = u, ot = 28),
    a.prototype.DB = ot,
    a.prototype.DM = (1 << ot) - 1,
    a.prototype.DV = 1 << ot;
    var pt = 52;
    a.prototype.FV = Math.pow(2, pt),
    a.prototype.F1 = pt - ot,
    a.prototype.F2 = 2 * ot - pt;
    var ct, ut, lt = "0123456789abcdefghijklmnopqrstuvwxyz",
    ht = new Array;
    for (ct = "0".charCodeAt(0), ut = 0; 9 >= ut; ++ut) ht[ct++] = ut;
    for (ct = "a".charCodeAt(0), ut = 10; 36 > ut; ++ut) ht[ct++] = ut;
    for (ct = "A".charCodeAt(0), ut = 10; 36 > ut; ++ut) ht[ct++] = ut;
    B.prototype.convert = M,
    B.prototype.revert = I,
    B.prototype.reduce = V,
    B.prototype.mulTo = j,
    B.prototype.sqrTo = L,
    F.prototype.convert = Q,
    F.prototype.revert = H,
    F.prototype.reduce = z,
    F.prototype.mulTo = P,
    F.prototype.sqrTo = U,
    a.prototype.copyTo = f,
    a.prototype.fromInt = g,
    a.prototype.fromString = d,
    a.prototype.clamp = _,
    a.prototype.dlShiftTo = k,
    a.prototype.drShiftTo = C,
    a.prototype.lShiftTo = $,
    a.prototype.rShiftTo = T,
    a.prototype.subTo = S,
    a.prototype.multiplyTo = D,
    a.prototype.squareTo = x,
    a.prototype.divRemTo = E,
    a.prototype.invDigit = N,
    a.prototype.isEven = O,
    a.prototype.exp = Z,
    a.prototype.toString = v,
    a.prototype.negate = y,
    a.prototype.abs = w,
    a.prototype.compareTo = b,
    a.prototype.bitLength = q,
    a.prototype.mod = R,
    a.prototype.modPowInt = W,
    a.ZERO = m(0),
    a.ONE = m(1);
    var ft, gt, mt;
    if (null == gt) {
        gt = new Array,
        mt = 0;
        var dt;
        if ("Netscape" == navigator.appName && navigator.appVersion < "5" && window.crypto && window.crypto.random) {
            var _t = window.crypto.random(32);
            for (dt = 0; dt < _t.length; ++dt) gt[mt++] = 255 & _t.charCodeAt(dt)
        }
        for (; vt > mt;) dt = Math.floor(65536 * Math.random()),
        gt[mt++] = dt >>> 8,
        gt[mt++] = 255 & dt;
        mt = 0,
        G()
    }
    Y.prototype.nextBytes = K,
    tt.prototype.init = et,
    tt.prototype.next = it;
    var vt = 256;
    return {
        rsa_encrypt: rt
    }
} (),
function(t) {
    function e() {
        return Math.round(4294967295 * Math.random())
    }
    function i(t, e, i) { (!i || i > 4) && (i = 4);
        for (var n = 0,
        r = e; e + i > r; r++) n <<= 8,
        n |= t[r];
        return (4294967295 & n) >>> 0
    }
    function n(t, e, i) {
        t[e + 3] = i >> 0 & 255,
        t[e + 2] = i >> 8 & 255,
        t[e + 1] = i >> 16 & 255,
        t[e + 0] = i >> 24 & 255
    }
    function r(t) {
        if (!t) return "";
        for (var e = "",
        i = 0; i < t.length; i++) {
            var n = Number(t[i]).toString(16);
            1 == n.length && (n = "0" + n),
            e += n
        }
        return e
    }
    function o(t) {
        for (var e = "",
        i = 0; i < t.length; i += 2) e += String.fromCharCode(parseInt(t.substr(i, 2), 16));
        return e
    }
    function a(t, e) {
        if (!t) return "";
        e && (t = s(t));
        for (var i = [], n = 0; n < t.length; n++) i[n] = t.charCodeAt(n);
        return r(i)
    }
    function s(t) {
        var e, i, n = [],
        r = t.length;
        for (e = 0; r > e; e++) i = t.charCodeAt(e),
        i > 0 && 127 >= i ? n.push(t.charAt(e)) : i >= 128 && 2047 >= i ? n.push(String.fromCharCode(192 | i >> 6 & 31), String.fromCharCode(128 | 63 & i)) : i >= 2048 && 65535 >= i && n.push(String.fromCharCode(224 | i >> 12 & 15), String.fromCharCode(128 | i >> 6 & 63), String.fromCharCode(128 | 63 & i));
        return n.join("")
    }
    function p(t) {
        _ = new Array(8),
        v = new Array(8),
        y = w = 0,
        q = !0,
        d = 0;
        var i = t.length,
        n = 0;
        d = (i + 10) % 8,
        0 != d && (d = 8 - d),
        b = new Array(i + d + 10),
        _[0] = 255 & (248 & e() | d);
        for (var r = 1; d >= r; r++) _[r] = 255 & e();
        d++;
        for (var r = 0; 8 > r; r++) v[r] = 0;
        for (n = 1; 2 >= n;) 8 > d && (_[d++] = 255 & e(), n++),
        8 == d && u();
        for (var r = 0; i > 0;) 8 > d && (_[d++] = t[r++], i--),
        8 == d && u();
        for (n = 1; 7 >= n;) 8 > d && (_[d++] = 0, n++),
        8 == d && u();
        return b
    }
    function c(t) {
        var e = 0,
        i = new Array(8),
        n = t.length;
        if (A = t, n % 8 != 0 || 16 > n) return null;
        if (v = h(t), d = 7 & v[0], e = n - d - 10, 0 > e) return null;
        for (var r = 0; r < i.length; r++) i[r] = 0;
        b = new Array(e),
        w = 0,
        y = 8,
        d++;
        for (var o = 1; 2 >= o;) if (8 > d && (d++, o++), 8 == d && (i = t, !f())) return null;
        for (var r = 0; 0 != e;) if (8 > d && (b[r] = 255 & (i[w + d] ^ v[d]), r++, e--, d++), 8 == d && (i = t, w = y - 8, !f())) return null;
        for (o = 1; 8 > o; o++) {
            if (8 > d) {
                if (0 != (i[w + d] ^ v[d])) return null;
                d++
            }
            if (8 == d && (i = t, w = y, !f())) return null
        }
        return b
    }
    function u() {
        for (var t = 0; 8 > t; t++) _[t] ^= q ? v[t] : b[w + t];
        for (var e = l(_), t = 0; 8 > t; t++) b[y + t] = e[t] ^ v[t],
        v[t] = _[t];
        w = y,
        y += 8,
        d = 0,
        q = !1
    }
    function l(t) {
        for (var e = 16,
        r = i(t, 0, 4), o = i(t, 4, 4), a = i(m, 0, 4), s = i(m, 4, 4), p = i(m, 8, 4), c = i(m, 12, 4), u = 0, l = 2654435769; e-->0;) u += l,
        u = (4294967295 & u) >>> 0,
        r += (o << 4) + a ^ o + u ^ (o >>> 5) + s,
        r = (4294967295 & r) >>> 0,
        o += (r << 4) + p ^ r + u ^ (r >>> 5) + c,
        o = (4294967295 & o) >>> 0;
        var h = new Array(8);
        return n(h, 0, r),
        n(h, 4, o),
        h
    }
    function h(t) {
        for (var e = 16,
        r = i(t, 0, 4), o = i(t, 4, 4), a = i(m, 0, 4), s = i(m, 4, 4), p = i(m, 8, 4), c = i(m, 12, 4), u = 3816266640, l = 2654435769; e-->0;) o -= (r << 4) + p ^ r + u ^ (r >>> 5) + c,
        o = (4294967295 & o) >>> 0,
        r -= (o << 4) + a ^ o + u ^ (o >>> 5) + s,
        r = (4294967295 & r) >>> 0,
        u -= l,
        u = (4294967295 & u) >>> 0;
        var h = new Array(8);
        return n(h, 0, r),
        n(h, 4, o),
        h
    }
    function f() {
        for (var t = (A.length, 0); 8 > t; t++) v[t] ^= A[y + t];
        return v = h(v),
        y += 8,
        d = 0,
        !0
    }
    function g(t, e) {
        var i = [];
        if (e) for (var n = 0; n < t.length; n++) i[n] = 255 & t.charCodeAt(n);
        else for (var r = 0,
        n = 0; n < t.length; n += 2) i[r++] = parseInt(t.substr(n, 2), 16);
        return i
    }
    var m = "",
    d = 0,
    _ = [],
    v = [],
    y = 0,
    w = 0,
    b = [],
    A = [],
    q = !0;
    TEA = {
        encrypt: function(t, e) {
            var i = g(t, e),
            n = p(i);
            return r(n)
        },
        enAsBase64: function(t, e) {
            for (var i = g(t, e), n = p(i), r = "", o = 0; o < n.length; o++) r += String.fromCharCode(n[o]);
            return k.encode(r)
        },
        decrypt: function(t) {
            var e = g(t, !1),
            i = c(e);
            return r(i)
        },
        initkey: function(t, e) {
            m = g(t, e)
        },
        bytesToStr: o,
        strToBytes: a,
        bytesInStr: r,
        dataFromStr: g
    };
    var k = {};
    k.PADCHAR = "=",
    k.ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    k.getbyte = function(t, e) {
        var i = t.charCodeAt(e);
        if (i > 255) throw "INVALID_CHARACTER_ERR: DOM Exception 5";
        return i
    },
    k.encode = function(t) {
        if (1 != arguments.length) throw "SyntaxError: Not enough arguments";
        var e, i, n = k.PADCHAR,
        r = k.ALPHA,
        o = k.getbyte,
        a = [];
        t = "" + t;
        var s = t.length - t.length % 3;
        if (0 == t.length) return t;
        for (e = 0; s > e; e += 3) i = o(t, e) << 16 | o(t, e + 1) << 8 | o(t, e + 2),
        a.push(r.charAt(i >> 18)),
        a.push(r.charAt(i >> 12 & 63)),
        a.push(r.charAt(i >> 6 & 63)),
        a.push(r.charAt(63 & i));
        switch (t.length - s) {
        case 1:
            i = o(t, e) << 16,
            a.push(r.charAt(i >> 18) + r.charAt(i >> 12 & 63) + n + n);
            break;
        case 2:
            i = o(t, e) << 16 | o(t, e + 1) << 8,
            a.push(r.charAt(i >> 18) + r.charAt(i >> 12 & 63) + r.charAt(i >> 6 & 63) + n)
        }
        return a.join("")
    },
    window.btoa || (window.btoa = k.encode)
} (window),
$ = window.$ || {},
$pt = window.$pt || {};
    function md5(t) {
        return hex_md5(t)
    }
    function hex_md5(t) {
        return binl2hex(core_md5(str2binl(t), t.length * chrsz))
    }
    function str_md5(t) {
        return binl2str(core_md5(str2binl(t), t.length * chrsz))
    }
    function hex_hmac_md5(t, e) {
        return binl2hex(core_hmac_md5(t, e))
    }
    function b64_hmac_md5(t, e) {
        return binl2b64(core_hmac_md5(t, e))
    }
    function str_hmac_md5(t, e) {
        return binl2str(core_hmac_md5(t, e))
    }
    function core_md5(t, e) {
        t[e >> 5] |= 128 << e % 32,
        t[(e + 64 >>> 9 << 4) + 14] = e;
        for (var i = 1732584193,
        n = -271733879,
        r = -1732584194,
        o = 271733878,
        a = 0; a < t.length; a += 16) {
            var s = i,
            p = n,
            c = r,
            u = o;
            i = md5_ff(i, n, r, o, t[a + 0], 7, -680876936),
            o = md5_ff(o, i, n, r, t[a + 1], 12, -389564586),
            r = md5_ff(r, o, i, n, t[a + 2], 17, 606105819),
            n = md5_ff(n, r, o, i, t[a + 3], 22, -1044525330),
            i = md5_ff(i, n, r, o, t[a + 4], 7, -176418897),
            o = md5_ff(o, i, n, r, t[a + 5], 12, 1200080426),
            r = md5_ff(r, o, i, n, t[a + 6], 17, -1473231341),
            n = md5_ff(n, r, o, i, t[a + 7], 22, -45705983),
            i = md5_ff(i, n, r, o, t[a + 8], 7, 1770035416),
            o = md5_ff(o, i, n, r, t[a + 9], 12, -1958414417),
            r = md5_ff(r, o, i, n, t[a + 10], 17, -42063),
            n = md5_ff(n, r, o, i, t[a + 11], 22, -1990404162),
            i = md5_ff(i, n, r, o, t[a + 12], 7, 1804603682),
            o = md5_ff(o, i, n, r, t[a + 13], 12, -40341101),
            r = md5_ff(r, o, i, n, t[a + 14], 17, -1502002290),
            n = md5_ff(n, r, o, i, t[a + 15], 22, 1236535329),
            i = md5_gg(i, n, r, o, t[a + 1], 5, -165796510),
            o = md5_gg(o, i, n, r, t[a + 6], 9, -1069501632),
            r = md5_gg(r, o, i, n, t[a + 11], 14, 643717713),
            n = md5_gg(n, r, o, i, t[a + 0], 20, -373897302),
            i = md5_gg(i, n, r, o, t[a + 5], 5, -701558691),
            o = md5_gg(o, i, n, r, t[a + 10], 9, 38016083),
            r = md5_gg(r, o, i, n, t[a + 15], 14, -660478335),
            n = md5_gg(n, r, o, i, t[a + 4], 20, -405537848),
            i = md5_gg(i, n, r, o, t[a + 9], 5, 568446438),
            o = md5_gg(o, i, n, r, t[a + 14], 9, -1019803690),
            r = md5_gg(r, o, i, n, t[a + 3], 14, -187363961),
            n = md5_gg(n, r, o, i, t[a + 8], 20, 1163531501),
            i = md5_gg(i, n, r, o, t[a + 13], 5, -1444681467),
            o = md5_gg(o, i, n, r, t[a + 2], 9, -51403784),
            r = md5_gg(r, o, i, n, t[a + 7], 14, 1735328473),
            n = md5_gg(n, r, o, i, t[a + 12], 20, -1926607734),
            i = md5_hh(i, n, r, o, t[a + 5], 4, -378558),
            o = md5_hh(o, i, n, r, t[a + 8], 11, -2022574463),
            r = md5_hh(r, o, i, n, t[a + 11], 16, 1839030562),
            n = md5_hh(n, r, o, i, t[a + 14], 23, -35309556),
            i = md5_hh(i, n, r, o, t[a + 1], 4, -1530992060),
            o = md5_hh(o, i, n, r, t[a + 4], 11, 1272893353),
            r = md5_hh(r, o, i, n, t[a + 7], 16, -155497632),
            n = md5_hh(n, r, o, i, t[a + 10], 23, -1094730640),
            i = md5_hh(i, n, r, o, t[a + 13], 4, 681279174),
            o = md5_hh(o, i, n, r, t[a + 0], 11, -358537222),
            r = md5_hh(r, o, i, n, t[a + 3], 16, -722521979),
            n = md5_hh(n, r, o, i, t[a + 6], 23, 76029189),
            i = md5_hh(i, n, r, o, t[a + 9], 4, -640364487),
            o = md5_hh(o, i, n, r, t[a + 12], 11, -421815835),
            r = md5_hh(r, o, i, n, t[a + 15], 16, 530742520),
            n = md5_hh(n, r, o, i, t[a + 2], 23, -995338651),
            i = md5_ii(i, n, r, o, t[a + 0], 6, -198630844),
            o = md5_ii(o, i, n, r, t[a + 7], 10, 1126891415),
            r = md5_ii(r, o, i, n, t[a + 14], 15, -1416354905),
            n = md5_ii(n, r, o, i, t[a + 5], 21, -57434055),
            i = md5_ii(i, n, r, o, t[a + 12], 6, 1700485571),
            o = md5_ii(o, i, n, r, t[a + 3], 10, -1894986606),
            r = md5_ii(r, o, i, n, t[a + 10], 15, -1051523),
            n = md5_ii(n, r, o, i, t[a + 1], 21, -2054922799),
            i = md5_ii(i, n, r, o, t[a + 8], 6, 1873313359),
            o = md5_ii(o, i, n, r, t[a + 15], 10, -30611744),
            r = md5_ii(r, o, i, n, t[a + 6], 15, -1560198380),
            n = md5_ii(n, r, o, i, t[a + 13], 21, 1309151649),
            i = md5_ii(i, n, r, o, t[a + 4], 6, -145523070),
            o = md5_ii(o, i, n, r, t[a + 11], 10, -1120210379),
            r = md5_ii(r, o, i, n, t[a + 2], 15, 718787259),
            n = md5_ii(n, r, o, i, t[a + 9], 21, -343485551),
            i = safe_add(i, s),
            n = safe_add(n, p),
            r = safe_add(r, c),
            o = safe_add(o, u)
        }
        return 16 == mode ? Array(n, r) : Array(i, n, r, o)
    }
    function md5_cmn(t, e, i, n, r, o) {
        return safe_add(bit_rol(safe_add(safe_add(e, t), safe_add(n, o)), r), i)
    }
    function md5_ff(t, e, i, n, r, o, a) {
        return md5_cmn(e & i | ~e & n, t, e, r, o, a)
    }
    function md5_gg(t, e, i, n, r, o, a) {
        return md5_cmn(e & n | i & ~n, t, e, r, o, a)
    }
    function md5_hh(t, e, i, n, r, o, a) {
        return md5_cmn(e ^ i ^ n, t, e, r, o, a)
    }
    function md5_ii(t, e, i, n, r, o, a) {
        return md5_cmn(i ^ (e | ~n), t, e, r, o, a)
    }
    function core_hmac_md5(t, e) {
        var i = str2binl(t);
        i.length > 16 && (i = core_md5(i, t.length * chrsz));
        for (var n = Array(16), r = Array(16), o = 0; 16 > o; o++) n[o] = 909522486 ^ i[o],
        r[o] = 1549556828 ^ i[o];
        var a = core_md5(n.concat(str2binl(e)), 512 + e.length * chrsz);
        return core_md5(r.concat(a), 640)
    }
    function safe_add(t, e) {
        var i = (65535 & t) + (65535 & e),
        n = (t >> 16) + (e >> 16) + (i >> 16);
        return n << 16 | 65535 & i
    }
    function bit_rol(t, e) {
        return t << e | t >>> 32 - e
    }
    function str2binl(t) {
        for (var e = Array(), i = (1 << chrsz) - 1, n = 0; n < t.length * chrsz; n += chrsz) e[n >> 5] |= (t.charCodeAt(n / chrsz) & i) << n % 32;
        return e
    }
    function binl2str(t) {
        for (var e = "",
        i = (1 << chrsz) - 1, n = 0; n < 32 * t.length; n += chrsz) e += String.fromCharCode(t[n >> 5] >>> n % 32 & i);
        return e
    }
    function binl2hex(t) {
        for (var e = hexcase ? "0123456789ABCDEF": "0123456789abcdef", i = "", n = 0; n < 4 * t.length; n++) i += e.charAt(t[n >> 2] >> n % 4 * 8 + 4 & 15) + e.charAt(t[n >> 2] >> n % 4 * 8 & 15);
        return i
    }
    function binl2b64(t) {
        for (var e = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        i = "",
        n = 0; n < 4 * t.length; n += 3) for (var r = (t[n >> 2] >> 8 * (n % 4) & 255) << 16 | (t[n + 1 >> 2] >> 8 * ((n + 1) % 4) & 255) << 8 | t[n + 2 >> 2] >> 8 * ((n + 2) % 4) & 255, o = 0; 4 > o; o++) i += 8 * n + 6 * o > 32 * t.length ? b64pad: e.charAt(r >> 6 * (3 - o) & 63);
        return i
    }
    function hexchar2bin(str) {
        for (var arr = [], i = 0; i < str.length; i += 2) arr.push("\\x" + str.substr(i, 2));
        return arr = arr.join(""),
        eval("var temp = '" + arr + "'"),
        temp
    }
    function __monitor(t, e) {
        if (! (Math.random() > (e || 1))) try {
            var i = location.protocol + "//ui.ptlogin2.qq.com/cgi-bin/report?id=" + t,
            n = document.createElement("img");
            n.src = i
        } catch(r) {}
    }
    function uin2hex(str) {
    for (var maxLength = 16,
    hex = parseInt(str).toString(16), len = hex.length, i = len; maxLength > i; i++) hex = "0" + hex;
    for (var arr = [], j = 0; maxLength > j; j += 2) arr.push("\\x" + hex.substr(j, 2));
    var result = arr.join("");
    return eval('result="' + result + '"'),
    result
}
    function getEncryption(t, e, i, n) {
        e = uin2hex(e);
        i = i || "",
        t = t || "";
        for (var r = n ? t: md5(t), o = hexchar2bin(r), a = md5(o + e), s = RSA.rsa_encrypt(o), p = (s.length / 2).toString(16), c = TEA.strToBytes(i.toUpperCase(), !0), u = Number(c.length / 2).toString(16); u.length < 4;) u = "0" + u;
        for (; p.length < 4;) p = "0" + p;
        TEA.initkey(a);
        var l = TEA.enAsBase64(p + s + TEA.strToBytes(e) + u + c);
        TEA.initkey("");
        __monitor(488358, 1);
        return l.replace(/[\/\+=]/g,
        function(t) {
            return {
                "/": "-",
                "+": "*",
                "=": "_"
            } [t];
        });
    }
    function getRSAEncryption(t, e, i) {
        var n = i ? t: md5(t),
        r = n + e.toUpperCase(),
        o = $.RSA.rsa_encrypt(r);
        return o
    }
    var hexcase = 1,
    b64pad = "",
    chrsz = 8,
    mode = 32;
""")

print("磁力解析开始：")
# 获取 verifycode，pt_verifysession_v1以及cookie
# 抓包得到你自己的url
url_step1 = 'http://check.ptlogin2.qq.com/check?pt_tea=1&uin=354929502&appid=567008010&js_ver=10151&js_type=0' \
            '&login_sig=&u1=http%3A%2F%2Flixian.qq.com%2Fmain.html&r=0.5916554303085995'
r = requests.get(url_step1)
dict_cookie = requests.utils.dict_from_cookiejar(r.cookies)
textView_step1 = re.findall("'(.*?)'", r.text)
verifycode = textView_step1[1]
pt_verifysession_v1 = textView_step1[3]
print('已获取Verification Code: ', verifycode)
print('已获取Check Verification Code: ', pt_verifysession_v1)
print('已获取cookie：ptvfsession and ptdrvs', dict_cookie)

user = '354929502'  # 你的QQ账号
# js函数的4个参数："你的QQ密码"，"你的QQ账号"，"你的验证码"，""
JSpassword_step2 = ctx.call("getEncryption", "你的QQ密码", "你的QQ账号", verifycode, "")
print('已计算出JS加密password：', JSpassword_step2)
# 抓包得到你自己的url
url_step2 = 'http://ptlogin2.qq.com/login?u='+user+'&p='+JSpassword_step2+'&verifycode='+verifycode+'&aid=567008010' \
            '&u1=http%3A%2F%2Flixian.qq.com%2Fmain.html&h=1&ptredirect=1&ptlang=2052&from_ui=1&dumy=&fp=loginerroralert' \
            '&action=1-13-175325&mibao_css=&t=1&g=1&js_type=0&js_ver=10151&login_sig=&pt_uistyle=1&pt_randsalt=0&pt_vcode_v1=0&pt_verifysession_v1='+pt_verifysession_v1
r = requests.get(url_step2, cookies=dict_cookie)
dict_cookie = dict_cookie.copy()
dict_cookie.update(requests.utils.dict_from_cookiejar(r.cookies))
skey = dict_cookie['skey']
print("已重新整合cookie：", dict_cookie)
print("已获取skey: ", skey)

ctx = execjs.compile(r"""
function getACSRFToken(str){
    var hash = 5381;
    for(var i = 0, len = str.length; i < len; ++i){
        hash += (hash << 5) + str.charCodeAt(i);
    }
    return hash & 0x7fffffff;
};
""")
g_tk = ctx.call("getACSRFToken", skey)
print("已计算出g_tk: ", g_tk)

print("登陆操作完毕: ", r.text)
inputfilename = input("请输入要解析的种子文件名称（请确保文件路径和程序在同一目录）: ")
# ------------------------------------------------------------------------登陆完成
url_step3 = 'http://lixian.qq.com/handler/lixian/do_lixian_login.php'
# post data
postdata_step3 = {
    'g_tk': g_tk
}
# header
headers_step3 = {
    'Referer': 'http://lixian.qq.com/main.html'
}
r = requests.post(url_step3, data=postdata_step3, cookies=dict_cookie, headers=headers_step3)
dict_cookie = dict_cookie.copy()
dict_cookie.update(requests.utils.dict_from_cookiejar(r.cookies))
print("已获取PHPSESSID: ", dict_cookie["PHPSESSID"])
print("已重新整合cookie: ", dict_cookie)

url_step4 = 'http://lixian.qq.com/handler/bt_handler.php?cmd=readinfo'
files = {
    'myfile': (inputfilename, open(inputfilename, 'rb'), 'application/octet-stream')  # 提交的种子文件
}
# header
headers_step4 = {
    'Referer': 'http://lixian.qq.com/main.html'
}
r = requests.post(url_step4, files=files, cookies=dict_cookie, headers=headers_step4)
r.encoding = 'utf-8-sig'
JSON_data = json.loads(r.text)
torrent_hash = JSON_data['hash']
taskname = JSON_data['name']
print('已获取torrent_hash: ', torrent_hash)
print('已获取taskname: ', taskname)
file_sizeALL = JSON_data['files']
size_index_filename = ()  # 保存有效的文件大小和索引以及文件名
for everysize in file_sizeALL:
    currentSize = "23" + str(everysize['file_size_ori'])  # 抓包分析提交的文件大小前加23
    currentIndex = everysize['file_index']
    currentFilename = everysize['file_name']
    size_index_filename = (currentSize, currentIndex, currentFilename)
    print("正在排除的数据：", size_index_filename)
    if int(currentSize) >= 231024000:  # 粗略的估计，去除非视频文件
        break;
filesize, index, filename = size_index_filename
print("当前选择的电影大小，索引，和名字: ", filesize, index, filename)

url_step5 = 'http://lixian.qq.com/handler/xfjson2012.php'
# header
headers_step5 = {
    'Referer': 'http://lixian.qq.com/main.html'
}
postdata_step5 = {
    'cmd': "add_bt_task",
    'r': "0.9633212021536193",
    'hash': torrent_hash,
    'taskname': taskname,
    'index': index,
    'filesize': filesize,
    'filename': filename
}
r = requests.post(url_step5, cookies=dict_cookie, headers=headers_step5, data=postdata_step5)
splitdata = re.findall('\"data\":\[(.*?)]}\)', r.text)
JSON_data = json.loads(splitdata[0])
mid = JSON_data['mid']
step5_filename = JSON_data['file_name']
print('已获取电影名：', step5_filename)
print('已获取mid: ', mid)

url_step6 = 'http://lixian.qq.com/handler/lixian/get_lixian_status.php'
# header
headers_step6 = {
    'Referer': 'http://lixian.qq.com/main.html'
}
postdata_step6 = {
    'mid': mid
}
r = requests.post(url_step6, cookies=dict_cookie, headers=headers_step6, data=postdata_step6)
JSON_data = json.loads(r.text)
hash_name = ()  # 用于保存file_hash和file_name
for everyfile in JSON_data['data']:
    file_hash = everyfile['hash']
    file_name = everyfile['file_name']
    hash_name = (file_hash, file_name)
    print("正在排除hash：", hash_name)
    if file_hash != '0000000000000000000000000000000000000000' and file_name == step5_filename:
        break
hash, filename = hash_name
if hash == '0000000000000000000000000000000000000000':
    isParseSuccessed = False
    print("file_hash排除失败，没有可靠的file_hash")
    print("解析失败！")
else:
    isParseSuccessed = True
    print('最终选择的file_hash, file_name: ', hash, filename)
    url_step7 = 'http://lixian.qq.com/handler/lixian/get_http_url.php'
    # header
    headers_step7 = {
        'Referer': 'http://lixian.qq.com/main.html'
    }
    postdata_step7 = {
        'hash': hash,
        'filename': filename,
        'browser': 'ie',
        'g_tk': g_tk
    }
    r = requests.post(url_step7, cookies=dict_cookie, headers=headers_step7, data=postdata_step7)
    print(r.text[3:])
    JSON_data = json.loads(r.text[3:])
    magnet = JSON_data['data']['com_url']
    ftn5k = JSON_data['data']['com_cookie']
    qqdownload = JSON_data['data']['xf_url']
    print('解析结果：')
    print("com_url：", magnet)
    print("com_cookie：", ftn5k)
    print("xf_url：", qqdownload)
    print("解析完毕！进入服务器删选阶段：")

if isParseSuccessed:
    url_header = ['http://xfxa.ctfs.ftn.qq.com', 'http://xfsh.ctfs.ftn.qq.com', 'http://xfcd.ctfs.ftn.qq.com',\
                  'http://xa.ctfs.ftn.qq.com', 'http://xa.btfs.ftn.qq.com', 'http://tj.ctfs.ftn.qq.com',\
                  'http://szmail.tfs.ftn.qq.com', 'http://sz.ctfs.ftn.qq.com', 'http://sh.ctfs.ftn.qq.com',\
                  'http://sh.btfs.ftn.qq.com', 'http://hz.ftn.qq.com', 'http://cd.ctfs.ftn.qq.com',\
                  'http://xg.ctfs.ftn.qq.com', 'http://xflx.xabtfs.ftn.qq.com', 'http://xflx.hz.ftn.qq.com'\
                  'http://sh.yun.ftn.qq.com', 'http://1.dc.ftn.qq.com', 'http://nj.disk.ftn.qq.com',\
                  'http://xasrc.ctfs.ftn.qq.com', 'http://cd-btfs.yunup.ftn.qq.com', 'http://xflx.store.cd.qq.com',\
                  'http://xflx.sz.ftn.qq.com']
    magnetCode = re.findall('ftn_handler/(.*?)/', magnet)
    final_magnet_url = None
    for everyheader in url_header:
        magnet_url = everyheader + '/ftn_handler/' + str(magnetCode[0]) + '?compressed=0&dtype=1&fname=m.mkv'
        finalCookie = {
            "FTN5K": ftn5k
        }
        try:
            with closing(requests.get(magnet_url, cookies=finalCookie, stream=True)) as r:
                print('正在排除服务器：', everyheader, r.headers['Content-Length'])
                print(int(filesize[2:]), r.headers['Content-Length'])
                if r.headers['Content-Length'] == filesize[2:]:
                    final_magnet_url = magnet_url
                    break
        except requests.exceptions.ConnectionError as err:
            print('服务器拒绝连接：' + everyheader)
    if final_magnet_url is not None:
        print("已获取可播放真实地址：" + magnet_url)
        print("可播放真实地址对应ftn5k：" + ftn5k)
        print("可播放真实地址对应文件名：" + filename)
        print("可播放真实地址对应文件大小：" + filesize[2:])
        print("加入播放引擎播放吧！")
    else:
        print("没有可播放真实地址！")




