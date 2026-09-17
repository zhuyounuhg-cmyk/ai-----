// pc_hook.js — phone-container 手机端测试容器 · 离线红队回放（v2.1）
// 运行环境：Frida Gadget（script 模式，宿主 guest 进程内）
// 功能：
//   1) 仅替换指定离线登录回包；org.json 探针不改变返回值与异常
//   2) android.support.little.MainActivity.UrlPost 返回值替换（主路径，与桌面版脚本同源）
//   3) decryRC4 / Toast 观察输出
//   4) 延时自动触发登录（测试用，可后续关闭）
// v1.5 变更（诊断增强）：
//   - UrlPost 打印所有首次出现的请求 URL（最多 40 条）→ 用于发现"公告/更新"接口
//   - 防护补丁增加探测输出与调用计数（guard probe / StartActivity.call #n）
//   - StartActivity.call 增加 invoke 转发兜底，避免无 apply 时误伤跳转
// v2.0 变更（登录后流程追踪）：
//   - 新增 MSDocker.pluginManager() 探针：一旦被调用即记录并打印调用栈（定位桥接入口）
//   - 新增 com.qihoo.magic.plugin.b.a(Z) 与 c.a(...) 调用追踪（容器桥接触发点）
//   - 新增 ContextImpl.startService / bindService / sendBroadcast 记录（各前 20 条 Intent）
// v2.1: nested payload, typed timestamps, scoped local-verifier tamper and flow evidence.
// v2.1b: secondary chain trace + click probe + secondary requestPermission guard.
// v2.1c: direct-kick mode — arm after AppEnterActivity flow, then startActivity(game) + OpenImgui().
'use strict';

var FAKE_LOGIN = '6029cfe82e3475f3965c91714a0a19545ebeebf4dd14ef7c90a1f11221cd74b43922e4e032f4a0c5f01cf2204d587077153c3aee679a68011ade19f0396c06250a8cc3183bda9d0f9750d38cc9b92e6e3d2e3e3babacc01326b43e64c1fb9788187fe5e1f99390d335fe6a354487f2b395930f20d4b04b812f416892f8970a3a3a4e195879fb04c06b33b994835a8ba246c026153a59c388d3546c4b7e137b792a8790877d6afd11bbdb5085371aa5cf6c4c2c355dd1e2c28c3957828a32a7f483c6252219f4565c2b561217bc501b6886998b7f85d5b58ceeba7313e572623cf7339b17f87a46214f3d29639b07048910507e89cefe739cfd0380e71210726631487871695b7cef';
var FAKE_UNBIND = '6029cfe82e3475f3965c91714a0a19545ebeebf4dd14ef7c90aecf0a23cb70b43922e4e032f4f1';
var FAKE_INI = '6029cfe82e3475f3965c91714a0a19545ebeebf4dd14ef7c903d348bb2159321d8dd6f368fecd0c5ab07f34a5c474f63117b2fd474db3b560d8822ba696243401087a95b529d8730d41399de7155e5efe1cfbdec4e3b26d026a24031afe083b25827f3a596d0858635eb6d081ccbe3e5f393045edafc769b370620';

var FIELDS = [
  'j51633c6e7eef176c3d98a29816a5e6ca',
  'w298fb9f406e1aabb59b',
  'a8ee5258f477bf953812ecb5a9229008b',
  'j0f32e705268d0058279119a80edd3b9d',
  'w4bece3811ea14e18175',
  't583a7458cf38dd94ceeaf75ca7eb40a6'
];

// 二级（android.mnb.xrk.MainActivity）回包字段组，按实际读取顺序记录即触发日志。
var SECONDARY_FIELDS = [
  'd347ef812f657a22035420e02c5a8930d',
  'h571dedc55ac14bcbed2034a1a9688bd3',
  'lbab38cd7679cd35d1d5dd01d520071fb',
  'j400cd29b0266277492681176b54a9780'
];

// Authorized offline red-team control, not a valid server signature.
var TAMPER_REPLAY_VERIFIER = true;
var TAMPER_SECONDARY_VERIFIER = false;
var replayTimestamp = 0;
var replaySignature = '00000000000000000000000000000000';

// 红队直驱模式（复现辅助）：②流程触到容器环境边界后，代为发起「启动游戏 + 辅助覆盖层」。
var DIRECT_KICK = true;
var directKickArmed = false;

// 二级回放变体（对照实验用）：418 = 现状默认；200 = 备用变体。
var SECONDARY_REPLAY_CODE = '418';

function shouldTamperDigest(input, callbackActive, secondary) {
  return (secondary ? TAMPER_SECONDARY_VERIFIER : TAMPER_REPLAY_VERIFIER) && callbackActive && replayTimestamp > 0 &&
    input.indexOf('' + replayTimestamp) === 0 && input.length > ('' + replayTimestamp).length;
}

function makeSecondaryReplay() {
  replayTimestamp = Math.floor(Date.now() / 1000);
  return JSON.stringify({
    d347ef812f657a22035420e02c5a8930d: SECONDARY_REPLAY_CODE,
    h571dedc55ac14bcbed2034a1a9688bd3: replaySignature,
    lbab38cd7679cd35d1d5dd01d520071fb: replayTimestamp,
    j400cd29b0266277492681176b54a9780: '{}'
  });
}

function log(m) {
  var message = '[PC] ' + m;
  try {
    console.log(message);
  } catch (e) {
  }
  try {
    if (androidLog) {
      androidLog.i('PC-Hook', message);
    }
  } catch (e) {
  }
}

var androidLog = null;

function isField(k) {
  for (var i = 0; i < FIELDS.length; i++) {
    if (FIELDS[i] === k) {
      return true;
    }
  }
  return false;
}

function isSecondaryField(k) {
  for (var i = 0; i < SECONDARY_FIELDS.length; i++) {
    if (SECONDARY_FIELDS[i] === k) {
      return true;
    }
  }
  return false;
}

function rewriteLoginReplay(ciphertext, plaintext) {
  if ('' + ciphertext !== FAKE_LOGIN) { return plaintext; }
  var replay = JSON.parse('' + plaintext);
  replayTimestamp = Math.floor(Date.now() / 1000);
  replay[FIELDS[3]] = '200';
  replay[FIELDS[2]] = replaySignature;
  replay[FIELDS[5]] = replayTimestamp;
  var payload = {};
  payload[FIELDS[1]] = replayTimestamp + 1800;
  payload[FIELDS[4]] = replayTimestamp + 1800;
  replay[FIELDS[0]] = JSON.stringify(payload);
  return JSON.stringify(replay);
}

var jsonHooksDone = false;

function installJsonHooks() {
  if (jsonHooksDone) {
    return;
  }
  jsonHooksDone = true;
  var J = Java.use('org.json.JSONObject');

  ['get', 'opt', 'getString', 'optString', 'getInt', 'optInt', 'getLong', 'optLong', 'getJSONObject', 'optJSONObject', 'has'].forEach(function (name) {
    J[name].overloads.forEach(function (o) {
      o.implementation = function () {
        var key = '' + arguments[0];
        var watched = isField(key) || isSecondaryField(key) || inGuestCallback();
        try {
          var result = o.apply(this, arguments);
          if (watched) { flowLog('JSON ' + name + ' ' + key + ' -> ' + flowValue(result)); }
          return result;
        } catch (e) {
          if (watched) { flowLog('JSON ' + name + ' ' + key + ' THROW ' + e); }
          throw e;
        }
      };
    });
  });
  log('read-only json probes installed');
}

// —— guest 类加载器定位（容器内应用由 DexClassLoader 载入） ——
function useGuestClass(name) {
  try {
    return Java.use(name);
  } catch (e) {
  }
  var found = null;
  try {
    Java.enumerateClassLoaders({
      onMatch: function (l) {
        if (found) {
          return;
        }
        try {
          l.loadClass(name);
          found = l;
        } catch (e) {
        }
      },
      onComplete: function () {
      }
    });
  } catch (e) {
    log('enumerateClassLoaders fail: ' + e);
  }
  if (found) {
    Java.classFactory.loader = found;
    try {
      return Java.use(name);
    } catch (e) {
      log('use after loader set fail: ' + e);
    }
  }
  return null;
}

var xriverHooksDone = false;
var seenUrls = {};
var seenUrlCount = 0;

// Read-only probes: a success message is not proof of an accepted login.
var flowThreads = {};
var flowProbeBusy = false;
var flowActivity = null;
var flowEvents = 0;

function inGuestCallback() {
  return !flowProbeBusy && !!flowThreads[Process.getCurrentThreadId()];
}

function flowLog(message) {
  if (flowProbeBusy || flowEvents >= 600) { return; }
  flowProbeBusy = true;
  try { flowEvents++; log('FLOW ' + message); }
  finally { flowProbeBusy = false; }
}

function flowValue(value) {
  var s = '' + value;
  return s.length <= 40 ? s : '<length=' + s.length + '>';
}

function dumpFlowViews() {
  if (!flowActivity) { return; }
  try {
    var V = Java.use('android.view.View');
    var TV = Java.use('android.widget.TextView');
    var fields = flowActivity.getClass().getDeclaredFields();
    for (var i = 0; i < fields.length; i++) {
      var f = fields[i];
      if (!V.class.isAssignableFrom(f.getType())) { continue; }
      f.setAccessible(true);
      var obj = f.get(flowActivity);
      if (obj === null) { continue; }
      var view = Java.cast(obj, V);
      var label = '';
      if (TV.class.isInstance(obj) && !Java.use('android.widget.EditText').class.isInstance(obj)) {
        label = ' text=' + Java.cast(obj, TV).getText();
      }
      flowLog('view ' + f.getName() + ' type=' + obj.getClass().getName() +
        ' visibility=' + view.getVisibility() + ' shown=' + view.isShown() +
        ' attached=' + view.isAttachedToWindow() + ' parent=' + (view.getParent() !== null) +
        ' size=' + view.getWidth() + 'x' + view.getHeight() + label);
    }
  } catch (e) { flowLog('view snapshot error=' + e); }
}

function installDigestProbe(MA) {
  var methods = MA.class.getDeclaredMethods();
  var digestMethods = {};
  var offCalls = {};
  for (var mi = 0; mi < methods.length; mi++) {
    var methodName = '' + methods[mi].getName();
    if (!/md5/i.test(methodName) || digestMethods[methodName]) { continue; }
    digestMethods[methodName] = true;
    MA[methodName].overloads.forEach(function (o) {
      o.implementation = function () {
        var result = o.apply(this, arguments);
        var active = inGuestCallback();
        var offCount = 0;
        if (!active) {
          offCount = (offCalls[methodName] || 0) + 1;
          offCalls[methodName] = offCount;
        }
        if (active || offCount <= 30) {
          var input = '' + arguments[0];
          flowLog((active ? '' : 'offcall ') + 'digest input.length=' + input.length + ' numericPrefix=' + (input.match(/^\d{1,10}/) || [''])[0] +
            ' output.length=' + ('' + result).length);
          if (active && shouldTamperDigest(input, true, MA.$className === 'android.mnb.xrk.MainActivity')) {
            flowLog('REDTEAM local verifier result replaced for offline replay');
            return replaySignature;
          }
        }
        return result;
      };
    });
    flowLog('installed digest probe ' + methodName);
  }
}

// —— 红队直驱（复现辅助）：②流程触到容器环境边界后，代为发起「启动游戏 + 辅助覆盖层」。
function scheduleDirectKick(reason) {
  if (!DIRECT_KICK || directKickArmed) { return; }
  directKickArmed = true;
  log('DIRECT KICK armed (reason=' + reason + ')');
  // 同步执行：②之后的进程可能被替换/重启，任何延时都不可靠。
  try { kickImgui(); } catch (e) { log('DIRECT KICK imgui outer fail: ' + e); }
  try { kickGame(); } catch (e) { log('DIRECT KICK game outer fail: ' + e); }
}

function kickGame() {
  try {
    var ctx = null;
    if (flowActivity && !flowActivity.isFinishing()) { ctx = flowActivity; }
    if (!ctx) {
      var app = Java.use('android.app.ActivityThread').currentApplication();
      if (app) { ctx = app.getApplicationContext(); }
    }
    if (!ctx) { log('DIRECT KICK game: no context'); return; }
    var Intent = Java.use('android.content.Intent');
    var it = Intent.$new();
    it.setClassName('com.tencent.tmgp.pubgmhd', 'com.epicgames.ue4.GameActivity');
    it.addFlags(0x10000000);
    log('DIRECT KICK game: startActivity com.tencent.tmgp.pubgmhd');
    ctx.startActivity(it);
  } catch (e) {
    log('DIRECT KICK game fail: ' + e);
  }
}

function kickImgui() {
  try {
    var called = false;
    Java.choose('android.mnb.xrk.MainActivity', {
      onMatch: function (inst) {
        if (called) { return; }
        called = true;
        log('DIRECT KICK imgui: OpenImgui()');
        try { inst.OpenImgui(); } catch (e2) { log('DIRECT KICK imgui call fail: ' + e2); }
      },
      onComplete: function () { }
    });
    if (!called) {
      Java.choose('android.support.little.MainActivity', {
        onMatch: function (inst) {
          if (called) { return; }
          called = true;
          log('DIRECT KICK imgui: outer OpenImgui()');
          try { inst.OpenImgui(); } catch (e3) { log('DIRECT KICK imgui outer fail: ' + e3); }
        },
        onComplete: function () { }
      });
    }
    if (!called) { log('DIRECT KICK imgui: no activity instance'); }
  } catch (e) {
    log('DIRECT KICK imgui fail: ' + e);
  }
}

function installDirectKickHook() {
  if (!DIRECT_KICK) { return; }
  log('DIRECT KICK ready (trigger=appenter)');
}

// —— 二级链路只读追踪：四字段读取之后调用了哪些方法（不改返回值与异常）。
function installSecondaryTrace(inner) {
  var traceNames = ['getAttributes', 'loadKmView', 'update', 'Notice', 'DeletePermission',
    '\u83b7\u53d6\u673a\u5668\u7801', '\u8bfb\u53d6\u6587\u4ef6', '\u6587\u4ef6\u662f\u5426\u5b58\u5728',
    '\u5199\u51faassets\u8d44\u6e90\u6587\u4ef6', '\u521b\u5efa\u6587\u4ef6', '\u5199\u5165\u6587\u4ef6',
    'Post', 'RC4Base', 'encryRC4String', 'encryRC4Byte', 'bytesToHex', 'hexToByte', 'initKey'];
  var counts = {};
  traceNames.forEach(function (name) {
    try {
      if (!inner[name] || !inner[name].overloads) { return; }
      inner[name].overloads.forEach(function (o) {
        o.implementation = function () {
          var c = counts[name] = (counts[name] || 0) + 1;
          var args = '';
          if (c <= 12) {
            var parts = [];
            for (var i = 0; i < arguments.length; i++) {
              try { parts.push(flowValue(arguments[i])); } catch (e0) { parts.push('<?>'); }
            }
            args = parts.join(', ');
          }
          try {
            var result = o.apply(this, arguments);
            if (c <= 12) { flowLog('TRACE ' + name + ' #' + c + ' args=[' + args + '] ret=' + flowValue(result)); }
            return result;
          } catch (e) {
            if (c <= 12) { flowLog('TRACE ' + name + ' #' + c + ' args=[' + args + '] THROW ' + e); }
            throw e;
          }
        };
      });
      flowLog('TRACE armed ' + name);
    } catch (e) {
      log('trace install fail ' + name + ': ' + e);
    }
  });
}

// —— 点击观测：记录被点击的 View（用于复现「①开启辅助」触发链）；只读。
function installClickProbe() {
  try {
    var V = Java.use('android.view.View');
    var TV = Java.use('android.widget.TextView');
    var pc = null;
    try { pc = V.performClick.overload(); } catch (e0) { pc = V.performClick; }
    var clicks = 0;
    pc.implementation = function () {
      clicks++;
      if (clicks <= 60) {
        var label = '';
        try {
          if (TV.class.isInstance(this)) {
            label = ' text=' + flowValue(Java.cast(this, TV).getText());
          }
        } catch (e2) {
        }
        flowLog('CLICK ' + this.getClass().getName() + label);
      }
      return pc.call(this);
    };
    log('click probe installed');
  } catch (e) {
    log('click probe fail: ' + e);
  }
}

function installSecondaryHooks() {
  var inner = useGuestClass('android.mnb.xrk.MainActivity');
  if (!inner) { flowLog('secondary class unavailable'); return; }
  installDigestProbe(inner);
  var methods = inner.class.getDeclaredMethods();
  var names = [];
  for (var i = 0; i < methods.length; i++) { names.push('' + methods[i].getName()); }
  flowLog('secondary runtime methods=' + names.join(','));
  installSecondaryTrace(inner);
  installClickProbe();
  installDirectKickHook();
  try {
    inner.requestPermission.overloads.forEach(function (o) {
      var rpType = o.returnType.className;
      o.implementation = function () {
        log('SECONDARY requestPermission skipped');
        if (rpType === 'boolean') { return true; }
        if (rpType === 'byte' || rpType === 'char' || rpType === 'short' ||
            rpType === 'int' || rpType === 'long' || rpType === 'float' ||
            rpType === 'double') { return 0; }
        if (rpType === 'void') { return undefined; }
        return null;
      };
    });
    log('SECONDARY requestPermission wrapped: ' + inner.requestPermission.overloads.length);
  } catch (e) {
    log('SECONDARY requestPermission wrap fail: ' + e);
  }
  inner['\u5199\u5165'].overloads.forEach(function (o) {
    o.implementation = function () {
      var args = Array.prototype.slice.call(arguments);
      if (args[1] === null && ('' + args[0]) === '/sdcard/imei') {
        args[1] = '862931040719305';
        flowLog('SECONDARY null device identifier normalized');
      }
      return o.apply(this, args);
    };
  });
  inner.UrlPost.overload('java.lang.String', 'java.lang.String').implementation = function (url, body) {
    flowLog('SECONDARY offline UrlPost ' + url);
    return ('' + url).indexOf('id=kmlogin') !== -1 ? 'PC_SECONDARY_OFFLINE_FIXTURE' : '';
  };
  var decode = inner.decryRC4.overload('java.lang.String', 'java.lang.String', 'java.lang.String');
  decode.implementation = function (a, b, c) {
    if ('' + a === 'PC_SECONDARY_OFFLINE_FIXTURE') { return makeSecondaryReplay(); }
    return decode.call(this, a, b, c);
  };
  inner.OpenImgui.overloads.forEach(function (o) {
    o.implementation = function () {
      flowLog('SECONDARY OpenImgui ENTER');
      try { var result = o.apply(this, arguments); flowLog('SECONDARY OpenImgui RETURN'); return result; }
      catch (e) { flowLog('SECONDARY OpenImgui THROW ' + e); throw e; }
    };
  });
  flowLog('secondary probes ready');
  Java.choose('android.mnb.xrk.MainActivity', {
    onMatch: function (instance) {
      if (!instance.isFinishing() && instance.hasWindowFocus()) {
        if (flowActivity) { flowActivity.$dispose(); }
        flowActivity = Java.retain(instance);
        return 'stop';
      }
    },
    onComplete: function () { Java.scheduleOnMainThread(dumpFlowViews); }
  });
}

function installFlowProbes(MA) {
  installDigestProbe(MA);
  var dispatch = Java.use('android.os.Handler').dispatchMessage.overload('android.os.Message');
  dispatch.implementation = function (msg) {
    var name = '' + this.getClass().getName();
    var guest = (name === 'android.support.little.MainActivity$100000010' ||
      name === 'android.mnb.xrk.MainActivity$100000010') && msg.what.value === 1;
    if (!guest) { return dispatch.call(this, msg); }
    var tid = Process.getCurrentThreadId();
    flowThreads[tid] = (flowThreads[tid] || 0) + 1;
    flowLog('callback ENTER class=' + this.getClass().getName() + ' what=' + msg.what.value);
    try { return dispatch.call(this, msg); }
    catch (e) { flowLog('callback THROW ' + e); throw e; }
    finally {
      flowLog('callback EXIT');
      flowThreads[tid]--;
      if (!flowThreads[tid]) { replayTimestamp = 0; }
      if (name === 'android.mnb.xrk.MainActivity$100000010' && DIRECT_KICK) {
        try { kickImgui(); } catch (e8) { log('DIRECT KICK imgui (a1) fail: ' + e8); }
      }
      Java.scheduleOnMainThread(dumpFlowViews);
    }
  };

  ['setContentView', 'OpenImgui'].forEach(function (name) {
    try {
      MA[name].overloads.forEach(function (o) {
        o.implementation = function () {
          if (!flowActivity) { flowActivity = Java.retain(this); }
          flowLog(name + ' ENTER');
          try { var result = o.apply(this, arguments); flowLog(name + ' RETURN'); return result; }
          catch (e) { flowLog(name + ' THROW ' + e); throw e; }
        };
      });
      flowLog('installed ' + name);
    } catch (e) { flowLog('install ' + name + ' error=' + e); }
  });

  var visibility = Java.use('android.view.View').setVisibility.overload('int');
  visibility.implementation = function (value) {
    if (inGuestCallback()) { flowLog('setVisibility ' + this.getClass().getName() + ' -> ' + value); }
    return visibility.call(this, value);
  };
  ['schedule', 'scheduleAtFixedRate'].forEach(function (name) {
    Java.use('java.util.Timer')[name].overloads.forEach(function (o) {
      o.implementation = function () {
        if (inGuestCallback()) { flowLog('Timer.' + name + ' delay/date=' + arguments[1]); }
        return o.apply(this, arguments);
      };
    });
  });
  Java.choose('android.support.little.MainActivity', {
    onMatch: function (instance) {
      if (!instance.isFinishing()) { flowActivity = Java.retain(instance); return 'stop'; }
    },
    onComplete: function () { Java.scheduleOnMainThread(dumpFlowViews); }
  });
  flowLog('probes ready');
}

function installActivityStartGuard() {
  var Activity = Java.use('android.app.Activity');
  var guardCalls = 0;
  Activity.startActivityForResult.overloads.forEach(function (o) {
    log('guard probe: apply=' + (typeof o.apply) + ',invoke=' + (typeof o.invoke) + ',call=' + (typeof o.call));
    o.implementation = function () {
      guardCalls++;
      if (guardCalls <= 30) {
        var desc = '';
        try {
          for (var ai = 0; ai < arguments.length; ai++) {
            var a = arguments[ai];
            if (a !== null && a !== undefined) {
              var cn = '';
              try {
                cn = a.getClass().getName();
              } catch (e0) {
              }
              if (cn === 'android.content.Intent') {
                desc = desc + ' [' + a.toString() + ']';
              }
            }
          }
        } catch (e1) {
        }
        log('startActivityForResult #' + guardCalls + desc);
      }
      try {
        return o.apply(this, arguments);
      } catch (e) {
        var message = '' + e;
        if (message.indexOf('does not belong to uid') !== -1) {
          log('startActivityForResult swallowed package/uid denial');
          return undefined;
        }
        throw e;
      }
    };
  });
  log('Activity.startActivityForResult guard installed');
  try {
    var startCalls = 0;
    Activity.startActivity.overloads.forEach(function (o) {
      o.implementation = function () {
        startCalls++;
        if (startCalls <= 30) {
          var desc = '';
          try {
            for (var ai = 0; ai < arguments.length; ai++) {
              var a = arguments[ai];
              if (a !== null && a !== undefined) {
                var cn = '';
                try {
                  cn = a.getClass().getName();
                } catch (e0) {
                }
                if (cn === 'android.content.Intent') {
                  desc = desc + ' [' + a.toString() + ']';
                }
              }
            }
          } catch (e1) {
          }
          log('startActivity #' + startCalls + desc);
          if (desc.indexOf('com.qihoo.magic.plugin.AppEnterActivity') !== -1) {
            scheduleDirectKick('appenter');
          }
        }
        return o.apply(this, arguments);
      };
    });
    log('Activity.startActivity logged');
  } catch (e) {
    log('startActivity log fail: ' + e);
  }
}

function installXriverHooksOnce() {
  if (xriverHooksDone) {
    return true;
  }
  var MA = useGuestClass('android.support.little.MainActivity');
  if (!MA) {
    return false;
  }
  log('MainActivity found');
  try { installFlowProbes(MA); }
  catch (e) { log('flow probes fail: ' + e); }
  try { installSecondaryHooks(); }
  catch (e) { log('secondary probes fail: ' + e); }

  try {
    MA.decryRC4.overload('java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function (a, b, c) {
      var r = this.decryRC4(a, b, c);
      r = rewriteLoginReplay(a, r);
      try {
        log('decryRC4 out=' + r);
      } catch (e) {
      }
      return r;
    };
  } catch (e) {
    log('decryRC4 hook fail: ' + e);
  }

  try {
    MA.UrlPost.overload('java.lang.String', 'java.lang.String').implementation = function (url, body) {
      var u = '' + url;
      try {
        if (!seenUrls[u]) {
          seenUrls[u] = 1;
          if (seenUrlCount < 40) {
            seenUrlCount++;
            log('UrlPost url=' + u + ' body.len=' + (body ? ('' + body).length : 0));
          }
        }
      } catch (e) {
      }
      try {
        if (u.indexOf('id=kmlogin') !== -1) {
          log('UrlPost -> FAKE LOGIN');
          return FAKE_LOGIN;
        }
        if (u.indexOf('id=kmunmachine') !== -1) {
          log('UrlPost -> FAKE UNBIND');
          return FAKE_UNBIND;
        }
        if (u.indexOf('id=ini') !== -1) {
          log('UrlPost -> FAKE INI');
          return FAKE_INI;
        }
      } catch (e) {
      }
      log('UrlPost blocked unhandled request in offline replay');
      return '';
    };
  } catch (e) {
    log('UrlPost hook fail: ' + e);
  }

  // —— 兼容修复：部分 ROM（如 vivo）对 guest 的 startActivity 做 uid/包名校验，
  //    导致 MainActivity.requestPermission（Dex2C native）抛 SecurityException 杀死进程。
  //    包住相关入口并吞掉异常，保住 guest 进程。
  try {
    var rpOverloads = MA.requestPermission.overloads;
    rpOverloads.forEach(function (o) {
      var returnType = o.returnType.className;
      o.implementation = function () {
        log('requestPermission skipped');
        if (returnType === 'boolean') {
          return true;
        }
        if (returnType === 'byte' || returnType === 'char' || returnType === 'short' ||
            returnType === 'int' || returnType === 'long' || returnType === 'float' ||
            returnType === 'double') {
          return 0;
        }
        if (returnType === 'void') {
          return undefined;
        }
        return null;
      };
    });
    log('requestPermission wrapped: ' + rpOverloads.length);
  } catch (e) {
    log('requestPermission wrap fail: ' + e);
  }

  // —— 点击「登录」时原生 onClick 会调用 MainActivity.写入(...)；容器环境下其字符串参数可能为 null，
  //    导致 Writer.write(null) NPE 崩溃（stage7 已定位）。包住它：null→''，并记录参数。
  try {
    var wrName = '\u5199\u5165'; // 写入
    var wrOverloads = MA[wrName].overloads;
    wrOverloads.forEach(function (o) {
      o.implementation = function () {
        var args = [];
        var nullFixed = false;
        var usePath = '';
        try {
          usePath = '' + arguments[0];
        } catch (e0b) {
        }
        for (var i = 0; i < arguments.length; i++) {
          if (arguments[i] === null) {
            nullFixed = true;
            args.push(usePath.indexOf('imei') !== -1 ? '862931040719305' : '');
          } else {
            args.push(arguments[i]);
          }
        }
        try {
          var dump = [];
          for (var j = 0; j < args.length; j++) {
            var s;
            try {
              s = ('' + args[j]);
            } catch (e2) {
              s = '<' + typeof args[j] + '>';
            }
            if (s.length > 100) {
              s = s.substring(0, 100) + '...';
            }
            dump.push(s);
          }
          log('\u5199\u5165 called nullFixed=' + nullFixed + ' args=' + dump.join(' | '));
        } catch (e3) {
        }
        try {
          return o.apply(this, args);
        } catch (e4) {
          log('\u5199\u5165 swallowed: ' + e4);
          return undefined;
        }
      };
    });
    log('\u5199\u5165 wrapped: ' + wrOverloads.length);
  } catch (e) {
    log('\u5199\u5165 wrap fail: ' + e);
  }

  try {
    var SAS = useGuestClass('com.lody.virtual.client.hook.proxies.am.MethodProxies$StartActivity');
    if (SAS) {
      var Integer = Java.use('java.lang.Integer');
      var sasCalls = 0;
      SAS.call.overloads.forEach(function (o) {
        log('SAS probe: apply=' + (typeof o.apply) + ',invoke=' + (typeof o.invoke) + ',call=' + (typeof o.call));
        o.implementation = function () {
          sasCalls++;
          if (sasCalls <= 20) {
            log('StartActivity.call #' + sasCalls);
          }
          try {
            if (o.apply) {
              return o.apply(this, arguments);
            }
            if (o.invoke) {
              return o.invoke(this, arguments);
            }
            log('StartActivity.call no-forwarder; returning 0');
            return Integer.valueOf(0);
          } catch (e) {
            log('StartActivity.call swallowed: ' + e);
            return Integer.valueOf(0);
          }
        };
      });
      log('StartActivity.call wrapped');
    } else {
      log('StartActivity class not found');
    }
  } catch (e) {
    log('StartActivity wrap fail: ' + e);
  }

  try {
    var Toast = Java.use('android.widget.Toast');
    Toast.makeText.overload('android.content.Context', 'java.lang.CharSequence', 'int').implementation = function (ctx, msg, d) {
      log('TOAST ' + msg);
      return this.makeText(ctx, msg, d);
    };
  } catch (e) {
    log('Toast hook fail: ' + e);
  }

  xriverHooksDone = true;
  log('xriver hooks installed');
  return true;
}

function tryTrigger() {
  var attempts = 0;
  var t = setInterval(function () {
    attempts++;
    if (attempts > 15) {
      clearInterval(t);
      return;
    }
    try {
      if (!useGuestClass('android.support.little.MainActivity')) {
        return;
      }
      Java.choose('android.support.little.MainActivity', {
        onMatch: function (instance) {
          try {
            if (instance.isFinishing() || !instance.hasWindowFocus()) { return; }
            log('trigger: activity found');
            var D = useGuestClass('android.support.little.MainActivity$D');
            if (D) {
              var runner = D.$new(instance);
              runner.run();
              log('trigger: run() invoked');
            }
          } catch (e) {
            log('trigger run err: ' + e);
          }
        },
        onComplete: function () {
        }
      });
      clearInterval(t);
    } catch (e) {
      log('trigger err: ' + e);
    }
  }, 4000);
}

// —— 无障碍崩溃防护：uiautomator 查询 TextView 时会走 isDeviceProvisioned → Settings.Global.getInt，
//    引擎的 SettingsProviderHook 在 vivo 上会抛 AttributionSource SecurityException（已定位），
//    该异常在 UI 线程未被捕获会杀死 guest。这里提前短路，避免读 Settings 提供者。
function installAccessibilityCrashGuard() {
  try {
    var SG = Java.use('android.provider.Settings$Global');
    SG.getInt.overloads.forEach(function (o) {
      o.implementation = function () {
        try {
          for (var i = 0; i < arguments.length; i++) {
            var s;
            try {
              s = '' + arguments[i];
            } catch (e) {
              s = '';
            }
            if (s === 'device_provisioned') {
              return 1;
            }
          }
        } catch (e) {
        }
        return o.apply(this, arguments);
      };
    });
    log('Settings.Global.getInt wrapped');
  } catch (e) {
    log('Settings.Global wrap fail: ' + e);
  }
  try {
    var TV = Java.use('android.widget.TextView');
    var m = TV.isDeviceProvisioned;
    if (m && m.overloads) {
      m.overloads.forEach(function (o) {
        o.implementation = function () {
          return true;
        };
      });
      log('TextView.isDeviceProvisioned -> true');
    }
  } catch (e) {
    log('TextView hook fail: ' + e);
  }
}

// —— 设备标识补齐：容器 guest 里 ANDROID_ID / IMEI 读取可能为空，
//    产品登录时会把设备码写入 /sdcard/imei 并用于后续流程。这里补一个固定假值。
function installDeviceIdHooks() {
  try {
    var Secure = Java.use('android.provider.Settings$Secure');
    Secure.getString.overloads.forEach(function (o) {
      o.implementation = function () {
        var r = o.apply(this, arguments);
        try {
          var name = '' + arguments[1];
          if (name === 'android_id' && (r === null || ('' + r).length === 0)) {
            log('android_id -> fake');
            return 'pc0a1b2c3d4e5f608';
          }
        } catch (e) {
        }
        return r;
      };
    });
    log('Settings.Secure.getString wrapped');
  } catch (e) {
    log('Secure wrap fail: ' + e);
  }
  try {
    var TM = Java.use('android.telephony.TelephonyManager');
    ['getImei', 'getMeid', 'getDeviceId', 'getSubscriberId'].forEach(function (m) {
      try {
        if (TM[m] && TM[m].overloads) {
          TM[m].overloads.forEach(function (o) {
            o.implementation = function () {
              return '862931040719305';
            };
          });
        }
      } catch (e2) {
      }
    });
    log('Telephony ids -> fake');
  } catch (e) {
    log('Telephony wrap fail: ' + e);
  }
}

// —— UI 探针：登录成功后界面的文字变化会走 setText，全部记录下来（前 80 次）。
function installUiProbes() {
  try {
    var TV = Java.use('android.widget.TextView');
    var n = 0;
    TV.setText.overload('java.lang.CharSequence').implementation = function (s) {
      n++;
      if (n <= 80) {
        var t = '';
        try {
          t = ('' + s);
        } catch (e) {
        }
        if (t.length > 60) {
          t = t.substring(0, 60) + '...';
        }
        log('setText #' + n + ' = ' + t);
      }
      return this.setText(s);
    };
    log('setText probe installed');
  } catch (e) {
    log('setText probe fail: ' + e);
  }
  try {
    var CI = Java.use('android.app.ContextImpl');
    var m = 0;
    CI.startActivity.overloads.forEach(function (o) {
      o.implementation = function () {
        m++;
        if (m <= 30) {
          var desc = '';
          try {
            for (var ai = 0; ai < arguments.length; ai++) {
              var a = arguments[ai];
              if (a !== null && a !== undefined) {
                var cn = '';
                try {
                  cn = a.getClass().getName();
                } catch (e0) {
                }
                if (cn === 'android.content.Intent') {
                  desc = desc + ' [' + a.toString() + ']';
                }
              }
            }
          } catch (e1) {
          }
          log('ContextImpl.startActivity #' + m + desc);
        }
        return o.apply(this, arguments);
      };
    });
    log('ContextImpl.startActivity logged');
  } catch (e) {
    log('ContextImpl wrap fail: ' + e);
  }
}

// —— 包管理器查询探针 + 分身大师（com.qihoo.magic）可见性修复
//    背景：guest 内查询 com.qihoo.magic 会 NameNotFoundException，导致直装的桥接检查失败、不启动游戏。
//    修复：查询失败时返回合成的 PackageInfo（versionCode=2218 + 真签名证书，证书 MD5 指纹
//    898e39e0dce87a5ced8bcdba460907bb 与桥接代码校验值一致）。
var QIHOO_CERT_B64 = 'MIIDhzCCAm+gAwIBAgIEdvt15zANBgkqhkiG9w0BAQsFADBzMQswCQYDVQQGEwI4NjERMA8GA1UECBMIY2hhb3lhbmcxEDAOBgNVBAcTB2JlaWppbmcxDjAMBgNVBAoTBXFpaG9vMRkwFwYDVQQLDBBxaWhvb19tb2JpbGVzYWZlMRQwEgYDVQQDEwtyZW50YWlzaGVuZzAgFw0xNjA0MjIxMTAwMTFaGA8yMDk4MDYxMTExMDAxMVowczELMAkGA1UEBhMCODYxETAPBgNVBAgTCGNoYW95YW5nMRAwDgYDVQQHEwdiZWlqaW5nMQ4wDAYDVQQKEwVxaWhvbzEZMBcGA1UECwwQcWlob29fbW9iaWxlc2FmZTEUMBIGA1UEAxMLcmVudGFpc2hlbmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCDkDPjlBUtjwNmsDTBPfk0yHCkCExDte85boZPtk38+nzRz5ovfYLeXl6eXzjt6HRB+4v8fVDOJSkhk2iop7JEIUZf3XKg2EcJpXbA2fphUJaLhoputEERr4J01SZHJ93GnXKEt4Lq/rzzPXiikR0d+rLEVU9sN/Ih6v2K0il7Y1XJKha1J2ykMZUzl9ByEcsfKNbiR9u9V2LGkSmUJEz7FKjVU8gg0eyNLcGb1XbHPD9xGK44JyiOeIpCDfQD5Zpx2BZbO361aBNSzlFxJ1ruRwOp8X2pTvKuckYrxyvfD8E7O1gVs73MvsH9WYJUAlNuGIAu50PUPLa8XJEk2E41AgMBAAGjITAfMB0GA1UdDgQWBBT+E8L7CkIiOaGIVdQWNCYReAY2nzANBgkqhkiG9w0BAQsFAAOCAQEABjJmxAq3BbN6CJFBPo8O2l26xv+lhyBf46Cyp+76tHj3KoqSP2BpgUxOOqD6gQiYoQVBPaF8Ax4Ufw9Dt2HZnYMBoa0RZ49qpKPoFfWBlCqEJDvNlCsiecFToaySKCTBqEqZ2e/gVWWic0Y+okiJbnR933BjrXPEc0YHRsEEHmBbpS7qBDM5z+eYn++bpA6utlQe3VwF3Bq/dsF4/kwwSeJvpGyjnJiCN8B7reddYun6wF8E9CS/QQko67L+ChJPffnwfY+BgBRxHXsa14DXct2Mjqda3M90b2lyyJqtxtE8ZUOh3/JVSfabfWBkPstFANiTLQRwfUFvEy7ig7yW0g==';

var fakeQihooPI = null;

function makeFakeQihooPI() {
  if (fakeQihooPI) {
    return fakeQihooPI;
  }
  var PI = Java.use('android.content.pm.PackageInfo');
  var pi = PI.$new();
  pi.packageName.value = 'com.qihoo.magic';
  pi.versionCode.value = 2218;
  pi.versionName.value = '5.3.3.1006';
  try {
    var der = Java.use('android.util.Base64').decode(QIHOO_CERT_B64, 0);
    var cf = Java.use('java.security.cert.CertificateFactory').getInstance('X.509');
    var bais = Java.use('java.io.ByteArrayInputStream').$new(der);
    var cert = cf.generateCertificate(bais);
    var sig = Java.use('android.content.pm.Signature').$new(cert.getEncoded());
    pi.signatures.value = Java.array('android.content.pm.Signature', [sig]);
    log('fake qihoo built: vc=2218 sig=1');
  } catch (e) {
    log('fake qihoo sig fail: ' + e);
  }
  fakeQihooPI = pi;
  return pi;
}

function makeFakeQihooAI() {
  var AI = Java.use('android.content.pm.ApplicationInfo');
  var ai = AI.$new();
  ai.packageName.value = 'com.qihoo.magic';
  ai.sourceDir.value = '/data/app/com.qihoo.magic/base.apk';
  ai.publicSourceDir.value = '/data/app/com.qihoo.magic/base.apk';
  ai.uid.value = 10000;
  return ai;
}

function installPmProbe() {
  try {
    var APM = Java.use('android.app.ApplicationPackageManager');
    var pc = 0;
    ['getPackageInfo', 'getApplicationInfo'].forEach(function (mn) {
      try {
        if (APM[mn] && APM[mn].overloads) {
          APM[mn].overloads.forEach(function (o) {
            o.implementation = function () {
              var pkg = '';
              try {
                pkg = '' + arguments[0];
              } catch (e) {
              }
              pc++;
              if (pc <= 60) {
                log('PMS ' + mn + ' ' + pkg);
              }
              if (pkg === 'com.qihoo.magic') {
                try {
                  return o.apply(this, arguments);
                } catch (e) {
                  log('PMS ' + mn + ' qihoo miss -> fake');
                  try {
                    return mn === 'getPackageInfo' ? makeFakeQihooPI() : makeFakeQihooAI();
                  } catch (e2) {
                    log('fake build fail: ' + e2);
                    throw e;
                  }
                }
              }
              return o.apply(this, arguments);
            };
          });
        }
      } catch (e2) {
      }
    });
    log('PMS probe installed');
  } catch (e) {
    log('PMS probe fail: ' + e);
  }
  try {
    APM.getLaunchIntentForPackage.overloads.forEach(function (o) {
      o.implementation = function () {
        var pkg = '';
        try {
          pkg = '' + arguments[0];
        } catch (e) {
        }
        if (pkg === 'com.qihoo.magic') {
          var Intent = Java.use('android.content.Intent');
          var it = Intent.$new('android.intent.action.MAIN');
          it.setPackage('com.qihoo.magic');
          log('getLaunchIntentForPackage(qihoo) -> fake');
          return it;
        }
        return o.apply(this, arguments);
      };
    });
    log('launchIntent hook installed');
  } catch (e4) {
    log('launchIntent hook fail: ' + e4);
  }
  setTimeout(function () {
    try {
      Java.perform(function () {
        try {
          var app = Java.use('android.app.ActivityThread').currentApplication();
          var pm = app.getPackageManager();
          var pi = pm.getPackageInfo('com.qihoo.magic', 64);
          var sigs = -1;
          try {
            sigs = pi.signatures.size();
          } catch (e3) {
          }
          log('qihoo.magic visible: versionCode=' + pi.versionCode.value + ' sigs=' + sigs);
        } catch (e) {
          log('qihoo probe err: ' + e);
        }
      });
    } catch (e) {
    }
  }, 8000);
}

// —— 桥接流程探针：容器 SDK（MSDocker）与 AppEnter 代理调用追踪 + 全方法级挂钩
function installBridgeProbes() {
  function hookAll(cls, tag, cap) {
    try {
      var ms = cls.class.getDeclaredMethods();
      var seen = {};
      for (var i = 0; i < ms.length; i++) {
        var nm = '' + ms[i].getName();
        if (nm.indexOf('<') === 0 || seen[nm]) { continue; }
        seen[nm] = true;
        (function (name) {
          try {
            var cnt = 0;
            cls[name].overloads.forEach(function (o) {
              try {
                o.implementation = function () {
                  cnt++;
                  if (cnt <= cap) { log('!! ' + tag + '.' + name + ' #' + cnt); }
                  return o.apply(this, arguments);
                };
              } catch (e1) {
              }
            });
          } catch (e2) {
          }
        })(nm);
      }
      log(tag + ' hookAll done: ' + ms.length + ' declared methods');
    } catch (e3) {
      log(tag + ' hookAll fail: ' + e3);
    }
  }
  try {
    var MSD = useGuestClass('com.qihoo.msdocker.MSDocker');
    if (MSD) {
      try {
        var mnames = [];
        var mms = MSD.class.getDeclaredMethods();
        for (var mi = 0; mi < mms.length; mi++) { mnames.push('' + mms[mi].getName()); }
        var mstr = mnames.join(',');
        if (mstr.length > 900) { mstr = mstr.substring(0, 900); }
        log('MSDocker methods: ' + mstr);
      } catch (e5) {
        log('MSD method desc fail: ' + e5);
      }
      hookAll(MSD, 'MSDocker', 5);
      MSD.pluginManager.overloads.forEach(function (o) {
        o.implementation = function () {
          log('MSDocker.pluginManager() called');
          try {
            var Throwable = Java.use('java.lang.Throwable');
            var Log = Java.use('android.util.Log');
            var st = '' + Log.getStackTraceString(Throwable.$new());
            var lines = st.split('\n');
            var keep = [];
            for (var li = 0; li < lines.length && keep.length < 8; li++) {
              var ln = lines[li];
              if (ln.indexOf('\tat ') === 0) {
                keep.push(ln.replace(/^\s*at /, ''));
              }
            }
            log('stack: ' + keep.join(' <- '));
          } catch (e0) {
          }
          return o.apply(this, arguments);
        };
      });
      log('MSDocker probe installed');
    } else {
      log('MSDocker not found');
    }
  } catch (e) {
    log('MSDocker probe fail: ' + e);
  }
  try {
    var B = useGuestClass('com.qihoo.magic.plugin.b');
    if (B) {
      hookAll(B, 'plugin.b', 5);
    } else {
      log('plugin.b not found');
    }
  } catch (e2) {
    log('b hook fail: ' + e2);
  }
  try {
    var PH = useGuestClass('com.qihoo.magic.plugin.PluginHelper');
    if (PH) {
      hookAll(PH, 'PluginHelper', 5);
    } else {
      log('PluginHelper not found');
    }
  } catch (e6) {
    log('PluginHelper hook fail: ' + e6);
  }
  try {
    var C = useGuestClass('com.qihoo.magic.plugin.c');
    if (C) {
      hookAll(C, 'plugin.c', 5);
    } else {
      log('plugin.c not found');
    }
  } catch (e4) {
    log('c hook fail: ' + e4);
  }
  try {
    var CI = Java.use('android.app.ContextImpl');
    ['startService', 'bindService', 'sendBroadcast'].forEach(function (mn) {
      try {
        var cnt2 = 0;
        CI[mn].overloads.forEach(function (o) {
          o.implementation = function () {
            cnt2++;
            if (cnt2 <= 20) {
              var desc = '';
              try {
                for (var ai = 0; ai < arguments.length; ai++) {
                  var a = arguments[ai];
                  if (a !== null && a !== undefined) {
                    var cn = '';
                    try {
                      cn = a.getClass().getName();
                    } catch (e9) {
                    }
                    if (cn === 'android.content.Intent') {
                      desc = desc + ' [' + a.toString() + ']';
                    }
                  }
                }
              } catch (e8) {
              }
              log('ContextImpl.' + mn + ' #' + cnt2 + desc);
            }
            return o.apply(this, arguments);
          };
        });
      } catch (e7) {
      }
    });
    log('ContextImpl svc/bcast hooked');
  } catch (e) {
    log('ContextImpl svc hook fail: ' + e);
  }
}

function main() {
  Java.perform(function () {
    androidLog = Java.use('android.util.Log');
    log('pc_hook boot v2.1-flow; java=' + (typeof Java !== 'undefined'));
    try {
      installActivityStartGuard();
    } catch (e) {
      log('Activity.startActivityForResult guard fail: ' + e);
    }
    installJsonHooks();
    try {
      installAccessibilityCrashGuard();
    } catch (e) {
      log('accessibility guard fail: ' + e);
    }
    try {
      installDeviceIdHooks();
    } catch (e) {
      log('device id hooks fail: ' + e);
    }
    try {
      installUiProbes();
    } catch (e) {
      log('ui probes fail: ' + e);
    }
    try {
      installPmProbe();
    } catch (e) {
      log('pm probe fail: ' + e);
    }
    try {
      installBridgeProbes();
    } catch (e) {
      log('bridge probes fail: ' + e);
    }
    var attempts = 0;
    var t = null;
    function attemptInstall() {
      attempts++;
      try {
        if (installXriverHooksOnce()) {
          clearInterval(t);
          return;
        }
      } catch (e) {
        log('install loop err: ' + e);
      }
      if (attempts > 20) {
        clearInterval(t);
        log('give up installing xriver hooks');
      }
    }
    attemptInstall();
    if (!xriverHooksDone) {
      t = setInterval(attemptInstall, 100);
    }
    setTimeout(tryTrigger, 12000);
  });
}

setImmediate(main);
