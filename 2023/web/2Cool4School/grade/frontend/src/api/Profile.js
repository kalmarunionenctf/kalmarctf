export async function getStudentProfile(id){
    let req = await fetch('/api/profile'+(id ? '/'+id : ''));
    return await req.json();
    /*return {
        name: 'John Doe',
        picture: 'https://www.w3schools.com/howto/img_avatar.png',
    }*/
}

export async function newProfile(name, file) {
    let picture = await parseFile(file)
    await fetch('/api/profile/new', {
        method: 'post',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({name: name, picture: picture})
    })
}

export async function updateName(name){
    await fetch('/api/profile', {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({name: name})
    })
}

export async function updatePicture(file){
    let picture = await parseFile(file)
    await fetch('/api/profile', {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({picture: picture})
    })
}

async function parseFile(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.readAsDataURL(file);
        reader.onload = () => resolve(reader.result);
        reader.onerror = error => reject(error);
    })
}