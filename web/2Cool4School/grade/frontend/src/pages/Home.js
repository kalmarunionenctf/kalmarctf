import * as React from 'react';
import Typography from '@mui/material/Typography';

class Home extends React.Component {
    render() {
        return (
            <div>
                <Typography sx={{
                    textAlign: 'center',
                    fontSize: 30,
                    fontWeight: 900
                }}>
                    Grade platform
                </Typography>
                <Typography sx={{
                    textAlign: 'center',
                    fontSize: 20,
                    fontWeight: 400
                }}>
                    Welcome to the Some University's grade platform. 
                    Here you can see your grades and other information about your courses grades.
                    It is only accessible for students and teachers.
                </Typography>
            </div>
        );
    }
}

export default Home;