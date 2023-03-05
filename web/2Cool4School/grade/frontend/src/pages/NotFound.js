import * as React from 'react';

import Typography from '@mui/material/Typography';

class NotFound extends React.Component {
    constructor(props) {
        super(props);
        // this.state = {
        //     courses: [],
        // };
    }

    async componentDidMount() {
        //const courses = await getCourses();
        //this.setState({ courses });
    }

    render() {
        //const { courses } = this.state;
        return (
            <div>
                <Typography sx={{
                    textAlign: 'center',
                    fontSize: 30,
                    fontWeight: 900
                }}>
                    Page not found
                </Typography>
                <Typography sx={{
                    textAlign: 'center',
                    fontSize: 20,
                    fontWeight: 400
                }}>
                    Huh... Seems like you are lost. Check if you have entered the right URL. 
                    If you have clicked a link and ended up here, please contact the author of the link to let them know.
                </Typography>
            </div>
        );
    }
}

export default NotFound;