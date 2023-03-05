export async function getGrades(id){
    let req = await fetch('/api/grades'+(id ? '/'+id : ''));
    if (req.status !== 200){
        return undefined;
    }
    return await req.json();
    /*
    return [
        {'name': 'Math', 'grade': 'B+', 'notes': 'Good job'},
        {'name': 'Algebra', 'grade': 'C', 'notes': 'Meh'},
        {'name': 'Fundamentals of Cyber Security', 'grade': 'A', 'notes': 'Meh'},
    ]*/
}

export async function updateGrades(id, name, comment){
    await fetch('/api/grades/'+id, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({name: name, values: { notes: comment}}),
    })
}

export async function requestReEvaluation() {
    await fetch('/whine', {
        method: 'post',
    })
}