const form=document.getElementById('login'),password=document.getElementById('password'),button=document.getElementById('submit'),message=document.getElementById('message');
document.getElementById('show').onclick=e=>{const show=password.type==='password';password.type=show?'text':'password';e.target.textContent=show?'Hide':'Show';e.target.setAttribute('aria-label',show?'Hide password':'Show password');};
form.onsubmit=async e=>{
  e.preventDefault();button.disabled=true;message.textContent='Signing in…';
  try {
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json','X-REA-Request':'workbench'},body:JSON.stringify({username:document.getElementById('username').value.trim(),password:password.value})});
    const data=await r.json();
    if(!r.ok)throw Error(data.error||'Sign-in failed.');
    password.value='';location.replace('/');
  }catch(err){message.textContent=err.message;button.disabled=false;}
};