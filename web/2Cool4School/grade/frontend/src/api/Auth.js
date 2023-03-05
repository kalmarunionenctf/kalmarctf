export async function getUser(){
    let req = await fetch('/api/profile/isNew');
    if (req.status !== 200){
        return undefined;
    }
    let isNew = await req.json();

    req = await fetch('/api/profile/role');
    let { role }  = await req.json();
    
    if (isNew){
        return {
            isNew: true,
            name: '',
            picture: '',
            role: role,
        }
    } else {
        req = await fetch('/api/profile');
        let profile = await req.json();
        return {
            isNew: false,
            name: profile.name,
            picture: profile.picture,
            role: role
        }  
    }

    /*
    return {
        isNew: false,
        name: "John Doe",
        role: "student",
        id: "123456789",
    }*/
}

export async function getFlag(){
    let req = await fetch('/flag');
    return await req.json();
}

export async function logout(){
    await fetch('/logout', {method: 'POST'})
}