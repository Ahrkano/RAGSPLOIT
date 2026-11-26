/* Monitor ao vivo compartilhado (aba Run e aba Casos de uso).
   Parseia o stream do PTY (marcadores que o pipeline ja imprime) e atualiza os
   contadores. Espera no DOM os ids: mTime, mIdle, mIdleBox, mLLM, mCve, mCred,
   mPhase, phases (com .ph[data-ph]), ports, portHint, cves.
   API: RSMonitor.reset()  antes de iniciar;  RSMonitor.feed(data) a cada
        mensagem do WS;  RSMonitor.stop() ao encerrar. */
window.RSMonitor = (function () {
  const PHASE_LABELS = {1:"Recon",2:"Análise (RAG+LLM)",3:"Exploração",
                        4:"Pós-exploração",5:"Privesc"};
  const mon = { startTs:0, lastDataTs:0, tick:null, llm:0, cred:0,
                cves:new Set(), ports:new Map(), target:null, phase:0,
                running:false, _buf:"" };
  const $ = id => document.getElementById(id);
  const stripAnsi = s => s.replace(/\x1b\[[0-9;?]*[A-Za-z]/g,"")
                          .replace(/\x1b[\]P].*?(\x07|\x1b\\)/g,"");

  function fmtDur(ms){
    const s=Math.max(0,Math.floor(ms/1000)); const m=Math.floor(s/60);
    return (m<60? String(m).padStart(2,"0")
                : String(Math.floor(m/60))+":"+String(m%60).padStart(2,"0"))
           + ":" + String(s%60).padStart(2,"0");
  }

  function reset(){
    mon.startTs=Date.now(); mon.lastDataTs=Date.now();
    mon.llm=0; mon.cred=0; mon.cves=new Set(); mon.ports=new Map();
    mon.target=null; mon.phase=0; mon.running=true; mon._buf="";
    if($("mTime")) $("mTime").textContent="00:00";
    if($("mLLM")) $("mLLM").textContent="0";
    if($("mCve")) $("mCve").textContent="0";
    if($("mCred")) $("mCred").textContent="0";
    if($("mPhase")) $("mPhase").textContent="—";
    if($("mIdle")) $("mIdle").textContent="0s";
    if($("mIdleBox")) $("mIdleBox").className="stat";
    if($("ports")) $("ports").innerHTML='<span class="hint">aguardando recon…</span>';
    if($("cves")) $("cves").innerHTML='<span class="hint">nenhum ainda</span>';
    document.querySelectorAll("#phases .ph").forEach(e=>e.className="ph");
    if(mon.tick) clearInterval(mon.tick);
    mon.tick=setInterval(tick, 500);
  }
  function stop(){ mon.running=false; if(mon.tick){clearInterval(mon.tick); mon.tick=null;} }

  function tick(){
    if(!mon.running) return;
    if($("mTime")) $("mTime").textContent=fmtDur(Date.now()-mon.startTs);
    const idle=Date.now()-mon.lastDataTs;
    if($("mIdle")) $("mIdle").textContent=Math.floor(idle/1000)+"s";
    const box=$("mIdleBox");
    if(box) box.className="stat"+(idle>20000?" bad":idle>8000?" warn":"");
  }

  function setPhase(n){
    if(n<1||n>5) return;
    mon.phase=n;
    if($("mPhase")) $("mPhase").textContent=n+" · "+(PHASE_LABELS[n]||"");
    document.querySelectorAll("#phases .ph").forEach(e=>{
      const p=+e.dataset.ph;
      e.className="ph"+(p<n?" done":p===n?" active":"");
    });
  }

  function renderPorts(){
    const box=$("ports"); if(!box) return;
    if(mon.ports.size===0){ box.innerHTML='<span class="hint">aguardando recon…</span>'; return; }
    box.innerHTML="";
    for(const [p,info] of mon.ports){
      const c=document.createElement("span");
      c.className="chip"+(info.state==="pwned"?" pwned":"")
                 +(p===mon.target&&info.state!=="pwned"?" target":"");
      let t="porta "+p; if(info.banner) t+=" · "+info.banner.slice(0,24);
      c.textContent=t;
      c.title=(info.banner||"")+(info.strategy?("\nestrategia: "+info.strategy):"")
              +(info.engine?("\nmotor: "+info.engine):"");
      box.appendChild(c);
    }
    const hint=$("portHint");
    if(hint){
      if(mon.target){
        const i=mon.ports.get(mon.target)||{};
        hint.textContent="— em teste: porta "+mon.target
          +(i.strategy?" ("+i.strategy+(i.engine?(" via "+i.engine):"")+")":"");
      } else hint.textContent="— a porta em teste fica destacada";
    }
  }
  function renderCves(){
    const box=$("cves"); if(!box) return;
    if(mon.cves.size===0){ box.innerHTML='<span class="hint">nenhum ainda</span>'; return; }
    box.innerHTML="";
    [...mon.cves].forEach(cve=>{
      const c=document.createElement("span"); c.className="chip cve"; c.textContent=cve;
      box.appendChild(c);
    });
  }

  function parseLine(line){
    let m;
    if((m=line.match(/>>>\s*\[FASE\s*(\d)\]/))) setPhase(+m[1]);
    if((m=line.match(/\[\+\]\s*Porta\s*(\d+)\s*:\s*(.*)$/))){
      const p=m[1];
      if(!mon.ports.has(p)) mon.ports.set(p,{banner:(m[2]||"").trim(),state:"open"});
      else mon.ports.get(p).banner=(m[2]||"").trim();
      renderPorts();
    }
    if((m=line.match(/ALVO:\s*PORTA\s*(\d+)/))){
      mon.target=m[1];
      if(!mon.ports.has(m[1])) mon.ports.set(m[1],{state:"open"});
      renderPorts();
    }
    if((m=line.match(/\[AI\]\s*Decisao:\s*([A-Z_]+)\s*\|\s*Modulo:\s*'([^']*)'/))){
      if(mon.target&&mon.ports.has(mon.target)){
        mon.ports.get(mon.target).strategy=m[1];
        const em=line.match(/MOTOR:\s*(.+?)\s*$/);
        if(em) mon.ports.get(mon.target).engine=em[1];
        renderPorts();
      }
    }
    if(/\[LLM\]\s*->/.test(line)){ mon.llm++; if($("mLLM")) $("mLLM").textContent=mon.llm; }
    if(/\[CRED\+\]/.test(line)){ mon.cred++; if($("mCred")) $("mCred").textContent=mon.cred; }
    const cm=line.match(/CVE-\d{4}-\d{3,7}/gi);
    if(cm){ cm.forEach(c=>mon.cves.add(c.toUpperCase()));
            if($("mCve")) $("mCve").textContent=mon.cves.size; renderCves(); }
    if(/\[\*\*\*\]|PWNED|SUCESSO ABSOLUTO|SUCESSO MANUAL/.test(line)){
      if(mon.target&&mon.ports.has(mon.target)){ mon.ports.get(mon.target).state="pwned"; renderPorts(); }
    }
  }

  function feed(data){
    mon.lastDataTs=Date.now();
    mon._buf += stripAnsi(data);
    let idx;
    while((idx=mon._buf.search(/\r?\n/))>=0){
      const line=mon._buf.slice(0,idx);
      mon._buf=mon._buf.slice(idx+(mon._buf[idx]==="\r"&&mon._buf[idx+1]==="\n"?2:1));
      if(line.trim()) parseLine(line);
    }
    if(mon._buf.length>4000) mon._buf=mon._buf.slice(-2000);
  }

  return { reset, feed, stop };
})();
