import { ethers } from 'hardhat';

// Role constants for AgglayerManager
export const DEFAULT_ADMIN_ROLE = ethers.ZeroHash;
export const ADD_ROLLUP_TYPE_ROLE = ethers.id('ADD_ROLLUP_TYPE_ROLE');
export const OBSOLETE_ROLLUP_TYPE_ROLE = ethers.id('OBSOLETE_ROLLUP_TYPE_ROLE');
export const CREATE_ROLLUP_ROLE = ethers.id('CREATE_ROLLUP_ROLE');
export const ADD_EXISTING_ROLLUP_ROLE = ethers.id('ADD_EXISTING_ROLLUP_ROLE');
export const UPDATE_ROLLUP_ROLE = ethers.id('UPDATE_ROLLUP_ROLE');
export const TRUSTED_AGGREGATOR_ROLE = ethers.id('TRUSTED_AGGREGATOR_ROLE');
export const TRUSTED_AGGREGATOR_ROLE_ADMIN = ethers.id('TRUSTED_AGGREGATOR_ROLE_ADMIN');
export const TWEAK_PARAMETERS_ROLE = ethers.id('TWEAK_PARAMETERS_ROLE');
export const SET_FEE_ROLE = ethers.id('SET_FEE_ROLE');
export const STOP_EMERGENCY_ROLE = ethers.id('STOP_EMERGENCY_ROLE');
export const EMERGENCY_COUNCIL_ROLE = ethers.id('EMERGENCY_COUNCIL_ROLE');
export const EMERGENCY_COUNCIL_ADMIN = ethers.id('EMERGENCY_COUNCIL_ADMIN');

// Role constants for AgglayerGateway
export const AGGCHAIN_DEFAULT_VKEY_ROLE = ethers.id('AGGCHAIN_DEFAULT_VKEY_ROLE');
export const AL_ADD_PP_ROUTE_ROLE = ethers.id('AL_ADD_PP_ROUTE_ROLE');
export const AL_FREEZE_PP_ROUTE_ROLE = ethers.id('AL_FREEZE_PP_ROUTE_ROLE');
export const AL_MULTISIG_ROLE = ethers.id('AL_MULTISIG_ROLE');