const DEFAULT_SETTINGS={realtime:true,archives:true,notifications:true,startup:false,close_to_tray:true};
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
 downloadSequence:0
};
function loadSettings(){try{return {...DEFAULT_SETTINGS,...JSON.parse(localStorage.getItem("guardian-demo-settings")||"{}")}}catch{return {...DEFAULT_SETTINGS}}}
function persistSettings(){localStorage.setItem("guardian-demo-settings",JSON.stringify(state.settings))}
function now(){return new Date().toLocaleString("en-GB",{day:"2-digit",month:"short",hour:"2-digit",minute:"2-digit"})}
function toast(title,text){const el=document.createElement("div");el.className="toast";el.innerHTML="<strong></strong><span></span>";el.querySelector("strong").textContent=title;el.querySelector("span").textContent=text;document.querySelector("#toast-region").append(el);setTimeout(()=>el.remove(),3500)}
function navigate(page){const toastRegion=document.querySelector("#toast-region");if(toastRegion)toastRegion.replaceChildren();document.querySelectorAll(".page").forEach(p=>p.classList.toggle("active",p.dataset.pagePanel===page));document.querySelectorAll(".nav-item[data-page]").forEach(b=>b.classList.toggle("active",b.dataset.page===page));if(page==="history")renderHistory();if(page==="quarantine")renderQuarantine();if(page==="settings")renderSettings()}
document.querySelectorAll("[data-page]").forEach(b=>b.addEventListener("click",()=>navigate(b.dataset.page)));
document.querySelectorAll("[data-action='quick-scan']").forEach(b=>b.addEventListener("click",()=>{navigate("overview");startScan("quick")}));
document.querySelectorAll("[data-action='home-scan']").forEach(b=>b.addEventListener("click",()=>{navigate("overview");startScan("home")}));
document.querySelectorAll("[data-scan]").forEach(b=>b.addEventListener("click",()=>startScan(b.dataset.scan)));
function updateProtection(){
 const on=state.settings.realtime;
 document.querySelector("#protection-status").textContent=on?"Folder monitoring is running":"Real-time monitoring off";
 document.querySelector("#protection-detail").textContent=on?"Real-Time Monitoring: Running · Browser demo uses safe simulated events.":"Real-Time Monitoring: Off · New demo files will not be automatically checked.";
 document.querySelector("#status-pill").textContent=on?"Protected":"Attention";
 document.querySelector("#protection-icon").textContent=on?"✓":"!";
}
function setScanningUi(active){
 state.scanning=active;
 document.querySelectorAll(".scan-option").forEach(b=>b.disabled=active);
 document.querySelector("#cancel-scan").classList.toggle("hidden",!active);
}
function getScanFiles(type){
 const source=type==="custom"?FILES.slice(0,5):type==="quick"?FILES.slice(0,8):FILES;
 const quarantined=new Set(state.quarantine.map(item=>item.path));
 return [...source,...(type==="custom"?[]:state.downloads)].filter(file=>!quarantined.has(file.path)&&!state.deletedPaths.has(file.path));
}
function startScan(type){
 if(state.scanning)return;
 const files=getScanFiles(type),label=type==="quick"?"Quick scan":type==="home"?"Home scan":"Demo folder scan";
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
 renderActivity();updateStats();
}
document.querySelector("#cancel-scan").addEventListener("click",()=>{if(state.scanning)state.cancelled=true});
function addHistory(path,result,details){state.history.unshift({time:now(),path,result,details});}
function addQuarantine(path,detection){state.quarantine.unshift({id:Date.now()+Math.random(),date:now(),path,detection});}
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
 if(state.settings.realtime){state.filesProcessed++;state.detections++;addHistory(path,"found",detection+" · real-time monitor");addQuarantine(path,detection);addActivity("Real-time detection","Sample quarantined automatically");if(state.settings.notifications)toast("Threat quarantined","Guardian isolated a safe simulated detection.");updateStats()}else{addActivity("Monitoring off","Sample was not automatically scanned");toast("Monitoring is off","Turn real-time monitoring on in Settings to auto-check new demo files.")}
 renderActivity();
}
document.querySelector("#simulate-download").addEventListener("click",simulateDownload);
function resultLabel(result){return result==="found"?"Detection":result==="clean"?"Clean":"Error"}
function filteredHistory(){
 const q=document.querySelector("#history-search").value.toLowerCase(),filter=document.querySelector("#history-filter").value;return state.history.filter(r=>(!filter||r.result===filter)&&(!q||(r.path+" "+r.details).toLowerCase().includes(q)));
}
function renderHistory(){
 const rows=filteredHistory();
 const body=document.querySelector("#history-body");body.innerHTML="";
 for(const r of rows){const tr=document.createElement("tr");for(const val of [r.time,r.path,resultLabel(r.result),r.details]){const td=document.createElement("td");td.textContent=val;tr.append(td)}tr.children[2].className="result-"+r.result;body.append(tr)}
 document.querySelector("#history-count").textContent=rows.length?"Showing "+rows.length+" of "+state.history.length+" recent results":"No results match the current filters.";
}
document.querySelector("#history-search").addEventListener("input",renderHistory);document.querySelector("#history-filter").addEventListener("change",renderHistory);
document.querySelector("#export-history").addEventListener("click",()=>{
 const rows=[["Time","File path","Result","Details"],...filteredHistory().map(r=>[r.time,r.path,resultLabel(r.result),r.details])];const csv=rows.map(row=>row.map(v=>'"'+String(v).replaceAll('"','""')+'"').join(",")).join("\n");const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([csv],{type:"text/csv"}));a.download="guardian-demo-history.csv";a.click();URL.revokeObjectURL(a.href);
});
function renderQuarantine(){
 const q=document.querySelector("#quarantine-search").value.toLowerCase();const rows=state.quarantine.filter(r=>(r.path+" "+r.detection).toLowerCase().includes(q));const body=document.querySelector("#quarantine-body");body.innerHTML="";
 for(const r of rows){const tr=document.createElement("tr");for(const val of [r.date,r.path,r.detection]){const td=document.createElement("td");td.textContent=val;tr.append(td)}const actions=document.createElement("td");actions.className="table-action";const restore=document.createElement("button");restore.className="btn secondary";restore.textContent="Restore";restore.addEventListener("click",()=>quarantineAction(r.id,"restore"));const del=document.createElement("button");del.className="btn danger";del.textContent="Delete";del.addEventListener("click",()=>quarantineAction(r.id,"delete"));actions.append(restore,del);tr.append(actions);body.append(tr)}
 document.querySelector("#quarantine-empty").style.display=rows.length?"none":"block";
}
document.querySelector("#quarantine-search").addEventListener("input",renderQuarantine);
function quarantineAction(id,action){const item=state.quarantine.find(q=>q.id===id);if(!item)return;state.quarantine=state.quarantine.filter(q=>q.id!==id);if(action==="delete")state.deletedPaths.add(item.path);else state.deletedPaths.delete(item.path);addActivity(action==="restore"?"File restored":"File permanently deleted",item.path);toast(action==="restore"?"Restored":"Deleted",action==="restore"?"Demo file restored to its original virtual path.":"Demo quarantine record permanently removed.");updateStats();renderQuarantine();renderActivity()}
function renderSettings(){document.querySelectorAll("[data-setting]").forEach(i=>i.checked=!!state.settings[i.dataset.setting]);updateProtection()}
document.querySelectorAll("[data-setting]").forEach(i=>i.addEventListener("change",()=>{state.settings[i.dataset.setting]=i.checked;persistSettings();updateProtection();toast("Settings saved","Changes applied to the interactive demo.")}));
document.querySelector("#restore-defaults").addEventListener("click",()=>{state.settings={...DEFAULT_SETTINGS};persistSettings();renderSettings();toast("Defaults restored","Guardian demo settings returned to defaults.")});
document.querySelector("#check-engine").addEventListener("click",()=>{document.querySelector("#engine-result").textContent="Native Guardian checks clamscan --version with a timeout and reports failures explicitly. This static demo cannot execute system binaries.";});
document.querySelector("#reset-demo").addEventListener("click",()=>{clearTimeout(state.scanTimer);state.history=[];state.quarantine=[];state.deletedPaths.clear();state.downloadSequence=0;state.downloads=[];state.filesProcessed=0;state.detections=0;state.scanning=false;state.cancelled=false;activity.length=0;setScanningUi(false);updateStats();renderActivity();renderHistory();renderQuarantine();document.querySelector("#history-search").value="";document.querySelector("#history-filter").value="";document.querySelector("#quarantine-search").value="";renderHistory();renderQuarantine();document.querySelector("#scan-state").textContent="Ready to scan";document.querySelector("#scan-count").textContent="0 / 0";document.querySelector("#progress-bar").style.width="0%";document.querySelector("#current-file").textContent="Scan results will appear here.";document.querySelector("#scan-summary").classList.add("hidden");navigate("overview");toast("Demo reset","Session data cleared; saved settings were retained.")});
updateProtection();updateStats();renderActivity();renderSettings();
window.__guardianDemo={startScan,simulateDownload,getState:()=>({filesProcessed:state.filesProcessed,detections:state.detections,quarantine:state.quarantine.length,history:state.history.length,realtime:state.settings.realtime,scanning:state.scanning,deleted:state.deletedPaths.size})};