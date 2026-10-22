const DEFAULT_SETTINGS={realtime:true,archives:true,notifications:true,startup:false,close_to_tray:true,scheduled_scan:false,weekly_home_scan:false,scan_hour:-1,quarantine_retention_days:0,theme:"system"};
const DEFAULT_FOLDERS={monitored:["/home/demo/Downloads","/home/demo/Desktop","/home/demo/Documents"],excluded:[]};
// SHA-256 of the harmless EICAR test file, which every demo sample stands in for.
const EICAR_SHA256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
const FILES=[
{path:"/home/demo/Downloads/coursework-notes.pdf",threat:null},
{path:"/home/demo/Desktop/project-plan.txt",threat:null},
{path:"/home/demo/Documents/cv.docx",threat:null},
{path:"/home/demo/Downloads/photos.zip",threat:null},
{path:"/home/demo/Documents/guardian-report.csv",threat:null},
{path:"/home/demo/Downloads/invoice-preview.pdf",threat:null},
{path:"/home/demo/Downloads/suspicious_sample.exe",threat:"EICAR-Test-Signature"},
{path:"/home/demo/Desktop/readme.md",threat:null},
{path:"/home/demo/Documents/archive.tar.gz",threat:null},
{path:"/home/demo/Downloads/app-installer.bin",threat:null},
{path:"/home/demo/Documents/notes.txt",threat:null},
{path:"/home/demo/Desktop/screenshot.png",threat:null}
];
const state={
 settings:loadSettings(),
 history:[],
 quarantine:[],
 filesProcessed:0,
 detections:0,
 scanning:false,
 cancelled:false,
 scanTimer:null,
 deletedPaths:new Set(),
 downloads:[],
 downloadSequence:0,
 folders:loadFolders(),
 pausedUntil:null
};
function loadSettings(){try{return {...DEFAULT_SETTINGS,...JSON.parse(localStorage.getItem("guardian-demo-settings")||"{}")}}catch{return {...DEFAULT_SETTINGS}}}
function persistSettings(){localStorage.setItem("guardian-demo-settings",JSON.stringify(state.settings))}
function loadFolders(){try{const saved=JSON.parse(localStorage.getItem("guardian-demo-folders")||"{}");return {monitored:Array.isArray(saved.monitored)?saved.monitored:[...DEFAULT_FOLDERS.monitored],excluded:Array.isArray(saved.excluded)?saved.excluded:[]}}catch{return {monitored:[...DEFAULT_FOLDERS.monitored],excluded:[]}}}
function persistFolders(){try{localStorage.setItem("guardian-demo-folders",JSON.stringify(state.folders))}catch{}}
function inFolder(path,folder){return path===folder||path.startsWith(folder.replace(/\/+$/,"")+"/")}
function isExcluded(path){return state.folders.excluded.some(folder=>inFolder(path,folder))}
function isMonitored(path){return state.folders.monitored.some(folder=>inFolder(path,folder))}
function paused(){if(state.pausedUntil&&Date.now()>=state.pausedUntil)state.pausedUntil=null;return !!state.pausedUntil}
function clock(time){return new Date(time).toLocaleTimeString("en-GB",{hour:"2-digit",minute:"2-digit"})}
function now(){return new Date().toLocaleString("en-GB",{day:"2-digit",month:"short",hour:"2-digit",minute:"2-digit"})}
function toast(title,text){const el=document.createElement("div");el.className="toast";el.innerHTML="<strong></strong><span></span>";el.querySelector("strong").textContent=title;el.querySelector("span").textContent=text;document.querySelector("#toast-region").append(el);setTimeout(()=>el.remove(),3500)}
function navigate(page){const toastRegion=document.querySelector("#toast-region");if(toastRegion)toastRegion.replaceChildren();document.querySelectorAll(".page").forEach(p=>p.classList.toggle("active",p.dataset.pagePanel===page));document.querySelectorAll(".nav-item[data-page]").forEach(b=>b.classList.toggle("active",b.dataset.page===page));if(page==="history")renderHistory();if(page==="quarantine")renderQuarantine();if(page==="settings")renderSettings()}
document.querySelectorAll("[data-page]").forEach(b=>b.addEventListener("click",()=>navigate(b.dataset.page)));
document.querySelectorAll("[data-action='quick-scan']").forEach(b=>b.addEventListener("click",()=>{navigate("overview");startScan("quick")}));
document.querySelectorAll("[data-action='home-scan']").forEach(b=>b.addEventListener("click",()=>{navigate("overview");startScan("home")}));
document.querySelectorAll("[data-scan]").forEach(b=>b.addEventListener("click",()=>startScan(b.dataset.scan)));
function updateProtection(){
 const isPaused=state.settings.realtime&&paused(),on=state.settings.realtime&&!isPaused;
 document.querySelector("#protection-status").textContent=isPaused?"Monitoring paused until "+clock(state.pausedUntil):on?"Folder monitoring is running":"Real-time monitoring off";
 document.querySelector("#protection-detail").textContent=isPaused?"Real-Time Monitoring: Paused · Resumes automatically.":on?"Real-Time Monitoring: Running · Browser demo uses safe simulated events.":"Real-Time Monitoring: Off · New demo files will not be automatically checked.";
 document.querySelector("#status-pill").textContent=on?"Protected":isPaused?"Paused":"Attention";
 document.querySelector("#protection-icon").textContent=on?"✓":"!";
 const pause=document.querySelector("#pause-monitoring");pause.textContent=isPaused?"Resume monitoring":"Pause monitoring for 1 hour";pause.classList.toggle("hidden",!state.settings.realtime);
}
document.querySelector("#pause-monitoring").addEventListener("click",()=>{state.pausedUntil=paused()?null:Date.now()+3600000;updateProtection();addActivity(state.pausedUntil?"Monitoring paused":"Monitoring resumed",state.pausedUntil?"Until "+clock(state.pausedUntil):"Real-time checks active");renderActivity()});
function setScanningUi(active){
 state.scanning=active;
 document.querySelectorAll(".scan-option").forEach(b=>b.disabled=active);
 document.querySelector("#cancel-scan").classList.toggle("hidden",!active);
}
function getScanFiles(type){
 const source=type==="files"?FILES.slice(5,7):type==="custom"?FILES.slice(0,5):type==="quick"?FILES.slice(0,8):FILES;
 const quarantined=new Set(state.quarantine.map(item=>item.path));
 return [...source,...(type==="custom"||type==="files"?[]:state.downloads)].filter(file=>!quarantined.has(file.path)&&!state.deletedPaths.has(file.path)&&!isExcluded(file.path));
}
function startScan(type){
 if(state.scanning)return;
 const files=getScanFiles(type),label=type==="quick"?"Quick scan":type==="home"?"Home scan":"Custom scan";state.scanStarted=Date.now();
 state.cancelled=false;setScanningUi(true);
 const stateEl=document.querySelector("#scan-state"),countEl=document.querySelector("#scan-count"),bar=document.querySelector("#progress-bar"),current=document.querySelector("#current-file"),summary=document.querySelector("#scan-summary");
 summary.classList.add("hidden");bar.style.width="0%";stateEl.textContent=label+" · Preparing";countEl.textContent="0 / "+files.length;current.textContent="Collecting files…";
 let i=0,clean=0,found=0,quarantined=0;
 const step=()=>{
  if(state.cancelled){finishScan(label,i,clean,found,quarantined,true);return}
  if(i>=files.length){finishScan(label,i,clean,found,quarantined,false);return}
  const file=files[i];i++;state.filesProcessed++;current.textContent=file.path;countEl.textContent=i+" / "+files.length;bar.style.width=Math.round(i/files.length*100)+"%";
  if(file.threat){found++;state.detections++;quarantined++;addQuarantine(file.path,file.threat);addHistory(file.path,"found",file.threat+" · quarantined")}else{clean++;addHistory(file.path,"clean","No threat found")}
  updateStats();state.scanTimer=setTimeout(step,280);
 };
 state.scanTimer=setTimeout(step,450);
}
function finishScan(label,scanned,clean,found,quarantined,cancelled){
 setScanningUi(false);state.scanTimer=null;document.querySelector("#scan-state").textContent=cancelled?"Scan cancelled":"Scan complete";document.querySelector("#current-file").textContent=scanned?scanned.toLocaleString()+" files processed":"No files checked.";
 const s=document.querySelector("#scan-summary");s.textContent="Clean: "+clean+"   •   Detections: "+found+"   •   Quarantined: "+quarantined+"   •   Errors: 0";s.classList.remove("hidden");
 addActivity(cancelled?"Scan cancelled":label,found?found+" detection(s), "+scanned+" files":scanned+" files clean");
 if(found&&state.settings.notifications)toast("Guardian detection",found+" safe demo sample quarantined.");
 const seconds=Math.max(1,Math.round((Date.now()-state.scanStarted)/1000));
 document.querySelector("#last-scan-line").textContent="Last scan: "+label+" "+(cancelled?"cancelled":"complete")+" · "+now()+" · "+scanned+" file"+(scanned===1?"":"s")+" in "+seconds+"s";
 renderActivity();updateStats();
}
document.querySelector("#cancel-scan").addEventListener("click",()=>{if(state.scanning)state.cancelled=true});
function addHistory(path,result,details){state.history.unshift({time:now(),ts:Date.now(),path,result,details});}
function addQuarantine(path,detection){state.quarantine.unshift({id:Date.now()+Math.random(),date:now(),path,detection,sha256:EICAR_SHA256});}
function updateStats(){document.querySelector("#stat-files").textContent=state.filesProcessed;document.querySelector("#stat-threats").textContent=state.detections;document.querySelector("#stat-quarantine").textContent=state.quarantine.length;const badge=document.querySelector("#quarantine-badge");badge.textContent=state.quarantine.length;badge.classList.toggle("hidden",!state.quarantine.length)}
const activity=[];
function addActivity(title,detail){activity.unshift({time:now(),title,detail});if(activity.length>6)activity.length=6}
function renderActivity(){const box=document.querySelector("#recent-activity");box.innerHTML="";const rows=activity.length?activity:[{time:"Now",title:"Guardian ready",detail:"Interactive demo loaded with safe sample data."}];for(const row of rows){const el=document.createElement("div");el.className="activity-item";el.innerHTML="<span></span><strong></strong><span></span>";el.children[0].textContent=row.time;el.children[1].textContent=row.title;el.children[2].textContent=row.detail;box.append(el)}}
function simulateDownload(){
 state.downloadSequence+=1;
 const filename="new_suspicious_sample_"+state.downloadSequence+".exe";
 const path="/home/demo/Downloads/"+filename,detection="EICAR-Test-Signature";
 state.downloads.push({path,threat:detection});
 addActivity("File created",filename);
 if(state.settings.realtime&&!paused()&&isMonitored(path)&&!isExcluded(path)){state.filesProcessed++;state.detections++;addHistory(path,"found",detection+" · real-time monitor");addQuarantine(path,detection);addActivity("Real-time detection","Sample quarantined automatically");if(state.settings.notifications)toast("Threat quarantined","Guardian isolated a safe simulated detection.");updateStats()}else{const why=!state.settings.realtime?"Turn real-time monitoring on in Settings to auto-check new demo files.":paused()?"Monitoring is paused; resume it on Overview.":"Downloads is not monitored or is excluded; check Settings.";addActivity("Not scanned automatically",filename);toast("Sample not checked",why)}
 renderActivity();
}
document.querySelector("#simulate-download").addEventListener("click",simulateDownload);
function resultLabel(result){return result==="found"?"Detection":result==="clean"?"Clean":"Error"}
function filteredHistory(){
 const q=document.querySelector("#history-search").value.toLowerCase(),filter=document.querySelector("#history-filter").value,days=Number(document.querySelector("#history-period").value),since=days?Date.now()-days*864e5:0;return state.history.filter(r=>(!filter||r.result===filter)&&r.ts>=since&&(!q||(r.path+" "+r.details).toLowerCase().includes(q)));
}
function renderHistory(){
 const rows=filteredHistory();
 const body=document.querySelector("#history-body");body.innerHTML="";
 for(const r of rows){const tr=document.createElement("tr");for(const val of [r.time,r.path,resultLabel(r.result),r.details]){const td=document.createElement("td");td.textContent=val;tr.append(td)}tr.children[2].className="result-"+r.result;body.append(tr)}
 document.querySelector("#history-count").textContent=rows.length?"Showing "+rows.length+" of "+state.history.length+" recent results":"No results match the current filters.";
}
document.querySelector("#history-search").addEventListener("input",renderHistory);document.querySelector("#history-filter").addEventListener("change",renderHistory);document.querySelector("#history-period").addEventListener("change",renderHistory);
function downloadCsv(rows,name){const csv=rows.map(row=>row.map(v=>{v=String(v??"");if(/^[=+\-@]/.test(v.trimStart()))v="'"+v;return '"'+v.replaceAll('"','""')+'"'}).join(",")).join("\n");const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([csv],{type:"text/csv"}));a.download=name;a.click();URL.revokeObjectURL(a.href)}
document.querySelector("#export-history").addEventListener("click",()=>{
 downloadCsv([["Time","File path","Result","Details"],...filteredHistory().map(r=>[r.time,r.path,resultLabel(r.result),r.details])],"guardian-demo-history.csv");
});
function renderQuarantine(){
 const rows=visibleQuarantine();const body=document.querySelector("#quarantine-body");body.innerHTML="";
 for(const r of rows){const tr=document.createElement("tr");for(const val of [r.date,r.path,r.detection,r.sha256.slice(0,12)+"…"]){const td=document.createElement("td");td.textContent=val;tr.append(td)}tr.children[3].title=r.sha256;const actions=document.createElement("td");actions.className="table-action";const copy=document.createElement("button");copy.className="btn secondary";copy.textContent="Copy SHA-256";copy.addEventListener("click",()=>copyHash(r.sha256));actions.append(copy);const restore=document.createElement("button");restore.className="btn secondary";restore.textContent="Restore";restore.addEventListener("click",()=>quarantineAction(r.id,"restore"));const del=document.createElement("button");del.className="btn danger";del.textContent="Delete";del.addEventListener("click",()=>quarantineAction(r.id,"delete"));actions.append(restore,del);tr.append(actions);body.append(tr)}
 document.querySelector("#quarantine-empty").style.display=rows.length?"none":"block";
 const n=state.quarantine.length;document.querySelector("#quarantine-usage").textContent=n?n+" file"+(n===1?"":"s")+" in quarantine · "+n*68+" bytes on disk":"";
 document.querySelector("#export-quarantine").disabled=!rows.length;
}
function visibleQuarantine(){const q=document.querySelector("#quarantine-search").value.toLowerCase();return state.quarantine.filter(r=>(r.path+" "+r.detection+" "+r.sha256).toLowerCase().includes(q))}
function copyHash(hash){const done=()=>toast("SHA-256 copied","Look the file up on a service such as VirusTotal without uploading it.");try{navigator.clipboard.writeText(hash).then(done,()=>toast("SHA-256",hash))}catch{toast("SHA-256",hash)}}
document.querySelector("#export-quarantine").addEventListener("click",()=>downloadCsv([["Date","Original file","Detection","SHA-256"],...visibleQuarantine().map(r=>[r.date,r.path,r.detection,r.sha256])],"guardian-demo-quarantine.csv"));
document.querySelector("#quarantine-search").addEventListener("input",renderQuarantine);
function quarantineAction(id,action){const item=state.quarantine.find(q=>q.id===id);if(!item)return;state.quarantine=state.quarantine.filter(q=>q.id!==id);if(action==="delete")state.deletedPaths.add(item.path);else state.deletedPaths.delete(item.path);addActivity(action==="restore"?"File restored":"File permanently deleted",item.path);toast(action==="restore"?"Restored":"Deleted",action==="restore"?"Demo file restored to its original virtual path.":"Demo quarantine record permanently removed.");updateStats();renderQuarantine();renderActivity()}
function renderSettings(){document.querySelectorAll("[data-setting]").forEach(i=>i.checked=!!state.settings[i.dataset.setting]);document.querySelectorAll("[data-choice]").forEach(s=>s.value=String(state.settings[s.dataset.choice]));renderFolders();applyTheme();updateProtection()}
function settingSaved(){persistSettings();updateProtection();applyTheme();toast("Settings saved","Changes applied to the interactive demo.")}
document.querySelectorAll("[data-choice]").forEach(s=>s.addEventListener("change",()=>{const key=s.dataset.choice;state.settings[key]=typeof DEFAULT_SETTINGS[key]==="number"?Number(s.value):s.value;settingSaved()}));
const lightQuery=window.matchMedia?matchMedia("(prefers-color-scheme: light)"):null;
function applyTheme(){const choice=state.settings.theme;document.documentElement.dataset.theme=choice==="system"?(lightQuery&&lightQuery.matches?"light":"dark"):choice}
if(lightQuery&&lightQuery.addEventListener)lightQuery.addEventListener("change",applyTheme);
function renderFolders(){for(const kind of ["monitored","excluded"]){const list=document.querySelector("#"+kind+"-list");list.innerHTML="";const folders=state.folders[kind];if(!folders.length){const li=document.createElement("li");li.className="muted";li.textContent=kind==="monitored"?"No folders monitored.":"No folders excluded.";list.append(li)}for(const folder of folders){const li=document.createElement("li");const span=document.createElement("span");span.textContent=folder;const remove=document.createElement("button");remove.className="btn secondary";remove.textContent="Remove";remove.setAttribute("aria-label","Remove "+folder);remove.addEventListener("click",()=>{state.folders[kind]=state.folders[kind].filter(f=>f!==folder);persistFolders();renderFolders();toast("Folder removed",folder)});li.append(span,remove);list.append(li)}}}
for(const kind of ["monitored","excluded"])document.querySelector("#"+kind+"-add").addEventListener("click",()=>{const input=document.querySelector("#"+kind+"-input"),folder=input.value.trim().replace(/\/+$/,"");if(!folder.startsWith("/")){toast("Enter a full path","Folders start with /, for example /home/demo/Projects.");return}if(!state.folders[kind].includes(folder))state.folders[kind].push(folder);input.value="";persistFolders();renderFolders();toast("Folder added",folder)});
document.querySelector("#show-onaccess").addEventListener("click",()=>{const pre=document.querySelector("#onaccess-steps");pre.textContent=["1. Add to /etc/clamav/clamd.conf:","",...state.folders.monitored.map(f=>"OnAccessIncludePath "+f),"OnAccessPrevention yes","OnAccessExcludeUname clamav","","2. Restart and enable on-access scanning:","","sudo systemctl restart clamav-daemon","sudo systemctl enable --now clamav-clamonacc"].join("\n");pre.classList.toggle("hidden")});
document.querySelector("#update-definitions").addEventListener("click",()=>{document.querySelector("#engine-result").textContent="Definitions are up to date (simulated). The native app runs freshclam and explains when the FreshClam service or administrator rights are needed.";});
document.querySelectorAll("[data-setting]").forEach(i=>i.addEventListener("change",()=>{state.settings[i.dataset.setting]=i.checked;if(i.dataset.setting==="realtime")state.pausedUntil=null;settingSaved()}));
document.querySelector("#restore-defaults").addEventListener("click",()=>{state.settings={...DEFAULT_SETTINGS};persistSettings();renderSettings();toast("Defaults restored","Guardian demo settings returned to defaults.")});
document.querySelector("#check-engine").addEventListener("click",()=>{document.querySelector("#engine-result").textContent="Native Guardian checks clamscan --version with a timeout and reports failures explicitly. This static demo cannot execute system binaries.";});
document.querySelector("#reset-demo").addEventListener("click",()=>{clearTimeout(state.scanTimer);state.history=[];state.quarantine=[];state.deletedPaths.clear();state.downloadSequence=0;state.downloads=[];state.filesProcessed=0;state.detections=0;state.scanning=false;state.cancelled=false;state.pausedUntil=null;activity.length=0;document.querySelector("#last-scan-line").textContent="No scans yet";setScanningUi(false);updateStats();renderActivity();renderHistory();renderQuarantine();document.querySelector("#history-search").value="";document.querySelector("#history-filter").value="";document.querySelector("#quarantine-search").value="";document.querySelector("#history-period").value="0";renderHistory();renderQuarantine();document.querySelector("#scan-state").textContent="Ready to scan";document.querySelector("#scan-count").textContent="0 / 0";document.querySelector("#progress-bar").style.width="0%";document.querySelector("#current-file").textContent="Scan results will appear here.";document.querySelector("#scan-summary").classList.add("hidden");navigate("overview");toast("Demo reset","Session data cleared; saved settings were retained.")});
updateProtection();updateStats();renderActivity();renderSettings();
window.__guardianDemo={startScan,simulateDownload,getState:()=>({filesProcessed:state.filesProcessed,detections:state.detections,quarantine:state.quarantine.length,history:state.history.length,realtime:state.settings.realtime,scanning:state.scanning,deleted:state.deletedPaths.size,paused:paused(),theme:document.documentElement.dataset.theme})};
setInterval(updateProtection,30000);