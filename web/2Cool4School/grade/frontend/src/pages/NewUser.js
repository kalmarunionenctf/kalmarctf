import * as React from 'react';

import Typography from '@mui/material/Typography';
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Stack from '@mui/material/Stack';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogTitle from '@mui/material/DialogTitle';

import './NewUser.css'

import { newProfile } from '../api/Profile';

const allowedFileExt = ['png', 'jpg', 'jpeg', 'svg']

class NewUser extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            profile: {
                name: '',
                picture: ''
            },
            file: undefined,
            dragActive: false,
            error: {
                open: false,
                title: '',
                body: ''
            },
        };
        this.inputRef = React.createRef();
    }

    handleDrag = (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (e.type === "dragenter" || e.type === "dragover") {
            this.setState({ dragActive: true });
        } else if (e.type === "dragleave") {
            this.setState({ dragActive: false });
        }
    };

    // triggers when file is dropped
    handleDrop = (e) => {
        e.preventDefault();
        e.stopPropagation();
        this.setState({ dragActive: false });
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            this.handleFiles(e.dataTransfer.files[0]);
        }
    };

    // triggers when file is selected with click
    handleChange = (e) => {
        e.preventDefault();
        if (e.target.files && e.target.files[0]) {
            this.handleFiles(e.target.files[0]);
        }
    };

    // triggers the input when the button is clicked
    onButtonClick = () => {
        this.inputRef.current.click();
    };

    handleFiles = (file) => {
        let fileparts = file.name.split(".")
        let fileext = fileparts[fileparts.length - 1]
        if (allowedFileExt.includes(fileext.toLowerCase())) {
            this.setState({ file });
        } else {
            this.setState({
                error: {
                    open: true,
                    title: 'Invalid file format',
                    body: 'The file you tried to upload is not valid. Please only upload images in the formats: JPG, PNG and SVG.'
                }
            })
        }
    };

    closeDialog = () => {
        this.setState({
            error: {
                open: false,
                title: '',
                body: ''
            }
        })
    }

    updateProfile = async () => {
        await newProfile(this.state.profile.name, this.state.file)
        this.props.callback()
    }

    
    updateField = (e) => {
        this.setState({profile: {name: e.target.value, picture: this.state.profile.picture}})
    } 

    render() {
        return (
            <>
                <Dialog
                    open={this.state.error.open}
                    onClose={() => this.closeDialog()}
                    aria-labelledby="alert-dialog-title"
                    aria-describedby="alert-dialog-description"
                >
                    <DialogTitle id="alert-dialog-title">
                        {this.state.error.title}
                    </DialogTitle>
                    <DialogContent>
                        <DialogContentText id="alert-dialog-description">
                            {this.state.error.body}
                        </DialogContentText>
                    </DialogContent>
                    <DialogActions>
                        <Button onClick={() => this.closeDialog()} autoFocus>
                            Ok
                        </Button>
                    </DialogActions>
                </Dialog>

                <Typography sx={{
                    textAlign: 'center',
                    fontSize: 30,
                    fontWeight: 900
                }}>
                    Welcome
                </Typography>
                <Typography sx={{
                    textAlign: 'center',
                    fontSize: 20,
                    fontWeight: 400
                }}>
                    Please configure your profile before continuing
                </Typography>
                <TextField id="name" label="Name" variant="outlined" value={this.state.profile.name} onChange={this.updateField} sx={{ width: '100%', marginTop: '5vh' }} />
                <form id="form-file-upload" onDragEnter={this.handleDrag} onSubmit={(e) => e.preventDefault()}>
                    <input ref={this.inputRef} accept="image/*" type="file" id="input-file-upload" onChange={this.handleChange} />
                    <label id="label-file-upload" htmlFor="input-file-upload" className={this.state.dragActive ? "drag-active" : ""} onClick={this.onButtonClick}>
                        {this.state.file ?
                            <Typography sx={{
                                textAlign: 'center',
                                fontSize: 20,
                                fontWeight: 400
                            }}>
                                {this.state.file.name}
                            </Typography>
                            :
                            <Typography sx={{
                                textAlign: 'center',
                                fontSize: 20,
                                fontWeight: 400,
                                margin: '1vw'
                            }}>
                                Drag and drop your new profile picture here or click to select a file
                            </Typography>
                        }
                    </label>
                    {this.state.dragActive && <div id="drag-file-element" onDragEnter={this.handleDrag} onDragLeave={this.handleDrag} onDragOver={this.handleDrag} onDrop={this.handleDrop}></div>}
                </form>
                <Stack direction="row-reverse" sx={{ marginTop: '5vh' }}>
                    { this.state.profile.name && this.state.file ? 
                    <Button variant="contained" onClick={this.updateProfile}>
                        Save
                    </Button>
                    :
                    <Button variant="contained" disabled>
                        Save
                    </Button>
                    }
                </Stack>
            </>
        );
    }
}
export default NewUser;