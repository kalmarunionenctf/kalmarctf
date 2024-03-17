import * as React from 'react';
import { Outlet } from 'react-router-dom';
import NavBar from './components/NavBar';

import Paper from '@mui/material/Paper';

class Layout extends React.Component {
    render() {
        return (
            <>
                <NavBar {...this.props}/>
                <Paper elevation={1} sx={{
                    width: '70vw',
                    margin: '5vh auto',
                    padding: '3vh 2vw 5vh 2vw',
                }}>
                    { this.props.ready? <Outlet/> : null }
                </Paper>
            </>
        )
    }
}

export default Layout;