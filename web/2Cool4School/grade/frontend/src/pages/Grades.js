import * as React from 'react';
import { useParams } from "react-router-dom";

import Typography from '@mui/material/Typography';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Paper from '@mui/material/Paper';
import EditIcon from '@mui/icons-material/Edit';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Modal from '@mui/material/Modal';
import TextField from '@mui/material/TextField';
import Stack from '@mui/material/Stack';

import { getGrades, updateGrades, requestReEvaluation } from '../api/Grades';
import { getFlag } from '../api/Auth';
import { getStudentProfile } from '../api/Profile';
import { Avatar } from '@mui/material';

const modalStyle = {
    position: 'absolute',
    top: '50%',
    left: '50%',
    transform: 'translate(-50%, -50%)',
    bgcolor: 'background.paper',
    boxShadow: 24,
    p: 4,
};

function withParams(Component) {
    return props => <Component {...props} params={useParams()} />;
}

class Grades extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            grades: [],
            editModal: {
                open: false,
                name: '',
                comment: ''
            },
            studentProfile: {
                name: '',
                picture: ''
            },
            flag: ''
        };
    }

    async componentDidMount() {
        if (this.props.params.id) {
            const grades = await getGrades(this.props.params.id);
            const studentProfile = await getStudentProfile(this.props.params.id);
            this.setState({ grades });
            this.setState({ studentProfile });
        } else {
            const grades = await getGrades();
            if (grades.find(grade => grade.name === 'Fundamentals of Cyber Security').grade === 'A') {
                const flag = await getFlag()
                this.setState({ flag })
            }
            this.setState({ grades });
        }
    }

    editNote = async (name) => {
        this.setState({
            editModal: {
                open: true,
                name: name,
                comment: this.state.grades.find(grade => grade.name === name).notes
            }
        });
    }

    updateField = (e) => {
        this.setState({ editModal: { ...this.state.editModal, comment: e.target.value } });
    }

    saveModal = async () => {
        await updateGrades(this.props.params.id, this.state.editModal.name, this.state.editModal.comment);
        this.state.grades = await getGrades(this.props.params.id);
        this.closeModal();
    }

    closeModal = () => {
        this.setState({
            editModal: {
                open: false,
                name: '',
                comment: ''
            }
        });
    }

    reEvaluation = async () => {
        await requestReEvaluation();
    }

    render() {
        const { grades } = this.state;
        return (
            <div>
                {this.props.user?.role === 'teacher' && this.props.params.id ?
                    <Stack direction="row" spacing={2} justifyContent="center" alignItems="center">
                        <Typography sx={{
                            textAlign: 'center',
                            fontSize: 30,
                            fontWeight: 900
                        }}>
                            Grades for {this.state.studentProfile?.name}
                        </Typography>
                        <Avatar alt={this.state.studentProfile?.name} src={this.state.studentProfile?.picture} />
                    </Stack>
                    :
                    <Typography sx={{
                        textAlign: 'center',
                        fontSize: 30,
                        fontWeight: 900
                    }}>
                        Grades
                    </Typography>
                }
                <Modal
                    open={Boolean(this.state.flag)}
                    aria-labelledby="modal-modal-title"
                    aria-describedby="modal-modal-description"
                >
                    <Box sx={modalStyle}>
                        <Typography id="modal-modal-title" variant="h6" component="h2" sx={{ textAlign: "center" }}>
                            You did good!
                        </Typography>
                        <Typography sx={{
                            textAlign: 'center',
                            fontSize: 18,
                            fontWeight: 700
                        }}>
                            Here's your flag: {this.state.flag}
                        </Typography>
                    </Box>
                </Modal>
                <Modal
                    open={this.state.editModal.open}
                    onClose={this.closeModal}
                    aria-labelledby="modal-modal-title"
                    aria-describedby="modal-modal-description"
                >
                    <Box sx={modalStyle}>
                        <Typography id="modal-modal-title" variant="h6" component="h2" sx={{ textAlign: "center" }}>
                            Change comment for {this.state.editModal.name}
                        </Typography>
                        <TextField
                            id="outlined-multiline-static"
                            label="Comment"
                            multiline
                            rows={4}
                            defaultValue={this.state.editModal.comment}
                            onChange={this.updateField}
                            sx={{ marginTop: '5vh' }}
                        />
                        <Stack direction="row" spacing={2} sx={{ marginTop: '5vh' }} justifyContent="space-between" alignItems="center">
                            <Button variant="contained" onClick={this.saveModal}>
                                Save
                            </Button>
                            <Button variant="contained" onClick={this.closeModal}>
                                Cancel
                            </Button>
                        </Stack>
                    </Box>
                </Modal>
                <Paper elevation={4}>
                    <TableContainer sx={{ margin: '2vh 0vw 0vh 0vw' }}>
                        <Table sx={{ minWidth: 650 }} aria-label="grades table">
                            <TableHead >
                                <TableRow>
                                    <TableCell align="center">
                                        <Typography sx={{
                                            textAlign: 'center',
                                            fontSize: 18,
                                            fontWeight: 700
                                        }}>
                                            Course
                                        </Typography>
                                    </TableCell>
                                    <TableCell align="center">
                                        <Typography sx={{
                                            textAlign: 'center',
                                            fontSize: 18,
                                            fontWeight: 700
                                        }}>
                                            Grades
                                        </Typography>
                                    </TableCell>
                                    <TableCell align="center">
                                        <Typography sx={{
                                            textAlign: 'center',
                                            fontSize: 18,
                                            fontWeight: 700
                                        }}>
                                            Comment
                                        </Typography>
                                    </TableCell>
                                    {this.props.user?.role === 'teacher' && this.props.params.id ?
                                        <TableCell align="center">
                                            <Typography sx={{
                                                textAlign: 'center',
                                                fontSize: 18,
                                                fontWeight: 700
                                            }}>
                                                Edit
                                            </Typography>
                                        </TableCell>
                                        : null}
                                </TableRow>
                            </TableHead>
                            <TableBody>
                                {grades.map((row) => (
                                    <TableRow
                                        key={row.name}
                                        sx={{ '&:last-child td, &:last-child th': { border: 0 } }}
                                    >
                                        <TableCell component="th" scope="row" align="center">
                                            {row.name}
                                        </TableCell>
                                        <TableCell align="center">{row.grade}</TableCell>
                                        <TableCell align="center">{row.notes}</TableCell>
                                        {this.props.user?.role === 'teacher' && this.props.params.id ?
                                            <TableCell align="center">
                                                <EditIcon
                                                    onClick={() => this.editNote(row.name)}
                                                    sx={{ cursor: 'pointer' }}
                                                />
                                            </TableCell>
                                            : null}
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    </TableContainer>
                </Paper>
                {this.props.user?.role === 'student' ?
                    <Stack direction="row" spacing={2} sx={{ marginTop: '5vh' }} justifyContent="space-between" alignItems="center">
                        <Typography sx={{
                            textAlign: 'center',
                            fontSize: 18,
                            fontWeight: 700
                        }}>
                            If you are not satisfied with your grades, you can ask for a re-evaluation.
                        </Typography>
                        <Button variant="contained" onClick={this.reEvaluation}>
                            Request Re-evaluation
                        </Button>
                    </Stack>
                    : null}
            </div>
        );
    }
}

export default withParams(Grades);