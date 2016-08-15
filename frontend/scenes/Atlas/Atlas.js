import React from 'react';
import { observer } from 'mobx-react';
import { Link, browserHistory } from 'react-router';
import keydown, { keydownScoped } from 'react-keydown';
import _ from 'lodash';

import store from './AtlasStore';

import Layout, { Title, HeaderAction } from 'components/Layout';
import AtlasPreviewLoading from 'components/AtlasPreviewLoading';
import CenteredContent from 'components/CenteredContent';
import DocumentList from 'components/DocumentList';
import Divider from 'components/Divider';
import DropdownMenu, { MenuItem, MoreIcon } from 'components/DropdownMenu';
import { Flex } from 'reflexbox';

import styles from './Atlas.scss';

@keydown(['c'])
@observer
class Atlas extends React.Component {
  componentDidMount = () => {
    const { id } = this.props.params;
    store.fetchCollection(id, data => {

      // Forward directly to root document
      if (data.type === 'atlas') {
        browserHistory.replace(data.navigationTree.url);
      }
    });
  }

  componentWillReceiveProps = (nextProps) => {
    const key = nextProps.keydown.event;
    if (key) {
      if (key.key === 'c') {
        _.defer(this.onCreate);
      }
    }
  }

  onCreate = (event) => {
    if (event) event.preventDefault();
    browserHistory.push(`${store.collection.url}/new`);
  }

  render() {
    const collection = store.collection;

    let actions;
    let title;
    let titleText;

    if (collection) {
      actions = (
        <Flex>
          <DropdownMenu label={ <MoreIcon /> } >
            <MenuItem onClick={ this.onCreate }>
              New document
            </MenuItem>
          </DropdownMenu>
        </Flex>
      );
      title = <Title>{ collection.name }</Title>;
      titleText = collection.name;
    }

    return (
      <Layout
        actions={ actions }
        title={ title }
        titleText={ titleText }
      >
        <CenteredContent>
          { store.isFetching ? (
            <AtlasPreviewLoading />
          ) : (
            <div className={ styles.container }>
              <div className={ styles.atlasDetails }>
                <h2>{ collection.name }</h2>
                <blockquote>
                  { collection.description }
                </blockquote>
              </div>

              <Divider />

              <DocumentList documents={ collection.recentDocuments } preview />
            </div>
          ) }
        </CenteredContent>
      </Layout>
    );
  }
}
export default Atlas;
