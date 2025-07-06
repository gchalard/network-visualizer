import React from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Typography,
  Grid,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Alert,
  Box,
  IconButton
} from '@mui/material';
import SecurityIcon from '@mui/icons-material/Security';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import CloseIcon from '@mui/icons-material/Close';

const VulnerabilityCard = ({ vulnerability, open, onClose }) => {
  const getCvssColor = (cvss) => {
    const score = parseFloat(cvss);
    if (score >= 9.0) return 'error';
    if (score >= 7.0) return 'warning';
    if (score >= 4.0) return 'info';
    return 'success';
  };

  const getCvssSeverity = (cvss) => {
    const score = parseFloat(cvss);
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Medium';
    return 'Low';
  };

  return (
    <Dialog 
      open={open} 
      onClose={onClose}
      maxWidth="md"
      fullWidth
    >
      <DialogTitle>
        <Box display="flex" alignItems="center" justifyContent="space-between">
          <Box display="flex" alignItems="center" gap={1}>
            <SecurityIcon color="error" />
            <Typography variant="h6">
              Vulnerability Details
            </Typography>
          </Box>
          <IconButton onClick={onClose}>
            <CloseIcon />
          </IconButton>
        </Box>
      </DialogTitle>
      <DialogContent>
        <Grid container spacing={3}>
          {/* Basic Information */}
          <Grid item xs={12}>
            <Typography variant="h6" gutterBottom>
              Basic Information
            </Typography>
            <TableContainer component={Paper} variant="outlined">
              <Table size="small">
                <TableBody>
                  <TableRow>
                    <TableCell component="th" sx={{ fontWeight: 'bold', width: '30%' }}>
                      Port
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={vulnerability.port} 
                        color="primary" 
                        size="small"
                      />
                    </TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell component="th" sx={{ fontWeight: 'bold' }}>
                      Service
                    </TableCell>
                    <TableCell>{vulnerability.service || 'Unknown'}</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell component="th" sx={{ fontWeight: 'bold' }}>
                      Product
                    </TableCell>
                    <TableCell>{vulnerability.product || 'Unknown'}</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell component="th" sx={{ fontWeight: 'bold' }}>
                      Version
                    </TableCell>
                    <TableCell>{vulnerability.version || 'Unknown'}</TableCell>
                  </TableRow>
                </TableBody>
              </Table>
            </TableContainer>
          </Grid>

          {/* CVEs Table */}
          <Grid item xs={12}>
            <Typography variant="h6" gutterBottom>
              Common Vulnerabilities and Exposures (CVEs)
            </Typography>
            {vulnerability.cpes && vulnerability.cpes.length > 0 ? (
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 'bold' }}>CVE ID</TableCell>
                      <TableCell sx={{ fontWeight: 'bold' }}>CVSS Score</TableCell>
                      <TableCell sx={{ fontWeight: 'bold' }}>Severity</TableCell>
                      <TableCell sx={{ fontWeight: 'bold' }}>Type</TableCell>
                      <TableCell sx={{ fontWeight: 'bold' }}>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {vulnerability.cpes.map((cpe, index) => (
                      <TableRow key={index} hover>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                            {cpe.id}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={cpe.cvss} 
                            color={getCvssColor(cpe.cvss)}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={getCvssSeverity(cpe.cvss)} 
                            color={getCvssColor(cpe.cvss)}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={cpe.type.toUpperCase()} 
                            variant="outlined"
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="outlined"
                            size="small"
                            startIcon={<OpenInNewIcon />}
                            href={cpe.ref}
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            View Details
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            ) : (
              <Alert severity="info">
                No CVEs found for this vulnerability.
              </Alert>
            )}
          </Grid>

          {/* Summary */}
          <Grid item xs={12}>
            <Alert 
              severity={vulnerability.cpes && vulnerability.cpes.some(cpe => parseFloat(cpe.cvss) >= 7.0) ? 'error' : 'warning'}
              icon={<SecurityIcon />}
            >
              <Typography variant="body2">
                <strong>Summary:</strong> This {vulnerability.service} service on port {vulnerability.port} 
                {vulnerability.product && vulnerability.product !== 'unknown' ? ` (${vulnerability.product})` : ''}
                {vulnerability.version && vulnerability.version !== 'unknown' ? ` version ${vulnerability.version}` : ''}
                {vulnerability.cpes && vulnerability.cpes.length > 0 
                  ? ` has ${vulnerability.cpes.length} known vulnerability/vulnerabilities.`
                  : ' has no known vulnerabilities.'
                }
              </Typography>
            </Alert>
          </Grid>
        </Grid>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} color="primary">
          Close
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default VulnerabilityCard; 